/**
 * Daemon 主服务：WSS 监听 + 配对窗口 + 设备注册表 + 命令队列整合。
 *
 * 启动后：
 *   - /pair 路径：配对连接（Noise_XX，msg3 载荷 = pair.req JSON）
 *   - /ws 路径：已配对设备的日常会话（hello 后开始收发命令）
 *
 * 状态访问：registry / queue / pairing / sessions（SessionManager）。
 */
import { createHash, randomBytes } from 'node:crypto'
import { WebSocketServer, type WebSocket as WsSocket } from 'ws'
import type { IncomingMessage } from 'node:http'
import { openDb, type Db } from './db'
import { Registry } from './registry'
import { OutboundQueue } from './queue'
import { WakeClient } from './wake'
import { PairingWindows, b64url } from './pairing'
import { SessionManager } from './sessions'
import { createResponderSession, type WireSession } from './session'
import { NoiseXX, type DHKey } from '../protocol/noise'
import { agentIdFromPub, deviceIdFromPub } from '../lib/ids'

export interface DaemonOptions {
  db: Db
  /** X25519 静态密钥（来自身份） */
  staticKey: DHKey
  /** 监听端口 */
  port: number
  host?: string
  /** 状态变化通知（供 MCP 壳/CLI 展示） */
  onLog?: (line: string) => void
  /** P4：本 daemon 的 agent_id（WakeClient 请求携带） */
  agentId?: string
  /** P4：Wake Gateway 配置；缺省 = 不启用唤醒 */
  wake?: { gatewayUrl: string; secret?: string }
}

export class Daemon {
  readonly registry: Registry
  readonly queue: OutboundQueue
  readonly pairing: PairingWindows
  readonly sessions: SessionManager
  #wss: WebSocketServer | null = null
  #staticKey: DHKey
  #log: (line: string) => void

  constructor(private readonly o: DaemonOptions) {
    this.registry = new Registry(o.db)
    this.queue = new OutboundQueue(o.db)
    this.pairing = new PairingWindows()
    this.sessions = new SessionManager(this.queue, this.registry, o.onLog ?? (() => {}))
    this.#staticKey = o.staticKey
    this.#log = o.onLog ?? ((l) => console.log(l))
    // P4：离线设备唤醒（gatewayUrl 未配置时 WakeClient 为 no-op）
    if (o.wake) {
      const client = new WakeClient({
        gatewayUrl: o.wake.gatewayUrl,
        secret: o.wake.secret,
        agentId: o.agentId ?? 'agent_unknown',
        agentPubHex: this.#staticKey.pub.toString('hex'),
        log: this.#log,
      })
      this.sessions.wakeHook = (devId: string) => {
        const dev = this.registry.get(devId)
        if (dev?.apns_token) {
          void client.wakeDevice(devId, { token: dev.apns_token, topic: dev.apns_topic ?? undefined })
        }
      }
    }
  }

  /** 打开一个配对窗口，返回口令 URI */
  openPairing(endpoints: string[], name?: string): string {
    return this.pairing.open({ k: b64url(this.#staticKey.pub), endpoints, name }).uri
  }

  listen(): Promise<number> {
    const wss = new WebSocketServer({ port: this.o.port, host: this.o.host })
    this.#wss = wss
    wss.on('connection', (ws: WsSocket, req: IncomingMessage) => {
      this.#onConnection(ws, req)
    })
    return new Promise((resolve) => {
      wss.on('listening', () => resolve(this.o.port))
    })
  }

  close(): void {
    this.#wss?.close()
    this.#wss = null
  }

  #onConnection(ws: WsSocket, req: IncomingMessage): void {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const noise = new NoiseXX(false, this.#staticKey)
    const id = `s_${randomBytes(6).toString('hex')}`
    this.#log(`连接进入：${url.pathname} (${id})`)

    createResponderSession(ws, {
      id,
      noise,
      events: {
        onHandshake: (remoteStatic) => {
          this.#log(`握手完成：对端 ${agentIdFromPub(remoteStatic)}`)
        },
        onJSON: (msg, session) => {
          try {
            this.#onMessage(msg, session, url.pathname)
          } catch (e) {
            this.#log(`处理消息出错：${(e as Error).message}`)
          }
        },
        onError: (e) => {
          this.#log(`会话错误：${e.message}`)
        },
        onClose: (session) => {
          this.sessions.offline(session)
          this.#log(`会话断开：${session.id}`)
        },
      },
    })
  }

  #onMessage(msg: Record<string, unknown>, session: WireSession, path: string): void {
    // 配对请求（配对路径专属）
    if (msg.t === 'pair.req') {
      this.#onPairReq(msg, session)
      return
    }
    if (path === '/pair') {
      session.send({ t: 'bye', reason: 'invalid' })
      session.close()
      return
    }

    // 日常会话：hello
    if (msg.t === 'hello') {
      const devId = String(msg.dev_id ?? '')
      const dev = this.registry.get(devId)
      if (!dev || dev.revoked_at !== null) {
        session.send({ t: 'bye', reason: 'unpaired' })
        session.close()
        return
      }
      this.registry.touch(devId)
      // P4：设备上线时顺带上报最新 APNs token（token 会随重装/系统更新变化）
      const apns = (msg.apns ?? null) as Record<string, unknown> | null
      if (apns && typeof apns.token === 'string' && apns.token.length > 0) {
        this.registry.upsert({
          devId,
          pub: dev.pub,
          alias: dev.alias,
          roles: dev.roles,
          scopes: dev.scopes,
          apns: {
            token: String(apns.token),
            env: apns.env === 'sandbox' ? 'sandbox' : 'prod',
            topic: typeof apns.topic === 'string' ? apns.topic : undefined,
          },
        })
      }
      this.sessions.online(devId, session)
      const pending = this.queue.pendingCount(devId)
      session.send({
        t: 'helloRes',
        ok: true,
        controller: dev.is_controller,
        scopes: dev.scopes,
        pending,
      })
      this.#log(`设备上线：${devId}（待补发 ${pending} 条）`)
      // 补发队列命令（TTL 内的）
      this.sessions.flush(devId)
      return
    }

    // 命令结果回包 / ack
    if ((msg.t === 'res' || msg.t === 'ack') && typeof msg.ref === 'string') {
      this.sessions.settle(msg.ref, msg)
      return
    }

    // ping/pong
    if (msg.t === 'ping') {
      session.send({ t: 'pong', id: msg.id })
      return
    }
  }

  /** 入队并立即尝试推给在线设备（不在线则留在队列，等 hello 补发） */
  submitCommand(input: Parameters<OutboundQueue['enqueue']>[0]): { ok: boolean; duplicate?: boolean; id: string } {
    return this.sessions.submit(input)
  }

  #onPairReq(msg: Record<string, unknown>, session: WireSession): void {
    const secret = String(msg.secret ?? '')
    const win = this.pairing.consume(secret)
    if (!win) {
      session.send({
        t: 'pair.res',
        status: 'rejected',
        reason: '口令无效或已过期',
        controller: false,
        scopes: 'operate',
      })
      session.close()
      return
    }

    const device = (msg.device ?? {}) as Record<string, unknown>
    const devPubRaw = session.noise.remoteStatic
    if (!devPubRaw) {
      session.send({
        t: 'pair.res',
        status: 'rejected',
        reason: '握手异常',
        controller: false,
        scopes: 'operate',
      })
      session.close()
      return
    }
    const devId = deviceIdFromPub(devPubRaw)
    const isFirst = this.registry.count() === 0
    const rec = this.registry.upsert({
      devId,
      pub: devPubRaw.toString('base64'),
      alias: device.name ? String(device.name) : null,
      roles: (msg.roles as string[]) ?? ['app'],
      scopes: 'manage',
    })
    if (isFirst) this.registry.claimController(devId)
    // SAS 确认码：SHA-256(agent公钥|设备公钥|口令) 前 6 位（双端各自可算出同值供人眼比对）
    const sas = createHash('sha256')
      .update(
        Buffer.concat([
          this.#staticKey.pub,
          devPubRaw,
          win.secret.length ? Buffer.from(win.secret) : Buffer.alloc(0),
        ]),
      )
      .digest()
    const sasCode = (BigInt(`0x${sas.toString('hex').slice(0, 12)}`) % 1_000_000n)
      .toString()
      .padStart(6, '0')

    session.send({
      t: 'pair.res',
      status: 'accepted',
      device_alias: rec.alias ?? devId,
      controller: isFirst,
      scopes: rec.scopes,
      agent: {
        id: agentIdFromPub(this.#staticKey.pub),
        name: 'anchor',
        version: '0.0.0',
        proto: [1],
      },
    })
    this.#log(`配对成功：${devId}${isFirst ? '（成为主控）' : ''}，SAS=${sasCode}`)
    // 保留连接：设备可在此连接上直接 hello 转入日常会话
  }
}
