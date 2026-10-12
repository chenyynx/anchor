/**
 * 模拟手机（假 AC）：发起 Noise_XX 握手 → pair.req → hello → 应答命令。
 * 用于 daemon 的端到端自测（P0 验收：pair→hello→命令往返）。
 */
import WebSocket from 'ws'
import { generateDH, NoiseXX } from '../src/protocol/noise'
import { deviceIdFromPub } from '../src/lib/ids'
import { parsePairingURI } from '../src/protocol/pairing-uri'

export interface MockPhoneOptions {
  url: string
  onLog?: (s: string) => void
}

interface MockPhoneInternals {
  o: MockPhoneOptions
  noise: NoiseXX
  ws: WebSocket | null
  log: (s: string) => void
  devId: string
  pub: Buffer
}

export class MockPhone {
  #i: MockPhoneInternals

  constructor(o: MockPhoneOptions) {
    const key = generateDH()
    this.#i = {
      o,
      noise: new NoiseXX(true, key),
      ws: null,
      log: o.onLog ?? ((s) => console.log(`[mock] ${s}`)),
      devId: deviceIdFromPub(key.pub),
      pub: key.pub,
    }
  }

  get devId(): string {
    return this.#i.devId
  }

  /** 连接配对 URI 对应端点，完成握手 + pair.req；resolve 于 pair.res */
  pair(uri: string, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const p = parsePairingURI(uri)
    return this.#run(p.endpoints[0] ?? p.endpoints[0]!, {
      t: 'pair.req',
      secret: p.s,
      ...extra,
      device: { id: this.#i.devId, name: '模拟手机', os: 'iOS 26.0', app_ver: '0.0.0' },
      roles: ['app', 'ext'],
      caps: {},
    })
  }

  /** 日常会话：hello */
  hello(): Promise<Record<string, unknown>> {
    return this.#send({
      t: 'hello',
      role: 'app',
      dev_id: this.#i.devId,
      proto: [1],
      caps: {},
    })
  }

  ping(): Promise<Record<string, unknown>> {
    return this.#send({ t: 'ping', id: `p_${Date.now()}` })
  }

  /** 内部：连接 + 握手 + 发送首帧（握手载荷或明文首条） */
  #run(endpoint: string, handshakePayload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const i = this.#i
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(endpoint)
      i.ws = ws
      let resolved = false
      ws.on('error', (e: Error) => {
        if (!resolved) reject(e)
      })
      ws.on('open', () => {
        i.log(`WS 已连接 ${endpoint}，发 msg1`)
        ws.send(i.noise.writeMsg1(), { binary: true })
      })
      const handler = (data: Buffer, isBinary: boolean) => {
        try {
          if (!isBinary) throw new Error('预期二进制帧')
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer)

          if (!i.noise.handshakeComplete) {
            i.log('收到 msg2，回 msg3（含首帧载荷）')
            i.noise.readMsg2(buf)
            const m3 = i.noise.writeMsg3(Buffer.from(JSON.stringify(handshakePayload), 'utf8'))
            ws.send(m3, { binary: true })
            return
          }
          const msg = JSON.parse(i.noise.recv(buf).toString('utf8')) as Record<string, unknown>
          i.log(`收到 ${msg.t}`)
          if (!resolved && (msg.t === 'pair.res' || msg.t === 'bye')) {
            resolved = true
            // 配对结束即摘除本监听器：后续消息交给 #send 挂的监听器处理，避免双解密
            ws.off('message', handler)
            resolve(msg)
            return
          }
          if (msg.t === 'cmd') {
            i.log(`应答命令 ${String(msg.op)}`)
            ws.send(
              i.noise.send(
                Buffer.from(
                  JSON.stringify({
                    t: 'res',
                    ref: msg.id,
                    ok: true,
                    status: 'applied',
                    data: {},
                  }),
                  'utf8',
                ),
              ),
              { binary: true },
            )
          }
        } catch (e) {
          if (!resolved) {
            resolved = true
            reject(e as Error)
          }
        }
      }
      ws.on('message', handler)
    })
  }

  #lastFrame: Buffer = Buffer.alloc(0)

  /** 已握手的会话上发送并等待响应帧 */
  #send(obj: Record<string, unknown>): Promise<Record<string, unknown>> {
    const i = this.#i
    return new Promise((resolve, reject) => {
      const ws = i.ws
      if (!ws || !i.noise.handshakeComplete) {
        reject(new Error('会话未建立'))
        return
      }
      const onMsg = (data: Buffer, isBinary: boolean) => {
        try {
          if (!isBinary) return
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer)
          const msg = JSON.parse(i.noise.recv(buf).toString('utf8')) as Record<string, unknown>
          if (msg.t === 'cmd') {
            i.log(`应答命令 ${String(msg.op)}`)
            ws.send(
              i.noise.send(
                Buffer.from(JSON.stringify({ t: 'res', ref: msg.id, ok: true, status: 'applied', data: {} }), 'utf8'),
              ),
              { binary: true },
            )
            return
          }
          ws.off('message', onMsg)
          resolve(msg)
        } catch (e) {
          ws.off('message', onMsg)
          reject(e as Error)
        }
      }
      ws.on('message', onMsg)
      ws.send(i.noise.send(Buffer.from(JSON.stringify(obj), 'utf8')), { binary: true })
    })
  }

  /** 常驻命令应答器：握手完成后调用一次，任何 cmd 帧自动回 applied */
  installAutoResponder(): void {
    const i = this.#i
    const ws = i.ws
    if (!ws || !i.noise.handshakeComplete) throw new Error('会话未建立')
    ws.on('message', (data: Buffer, isBinary: boolean) => {
      try {
        if (!isBinary) return
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer)
        const msg = JSON.parse(i.noise.recv(buf).toString('utf8')) as Record<string, unknown>
        if (msg.t === 'cmd') {
          i.log('[auto] reply ' + String(msg.op))
          ws.send(
            i.noise.send(
              Buffer.from(JSON.stringify({ t: 'res', ref: msg.id, ok: true, status: 'applied', data: {} }), 'utf8'),
            ),
            { binary: true },
          )
        }
      } catch {
        /* 解密失败或非 cmd：忽略，交给其它监听器 */
      }
    })
  }

  close(): void {
    this.#i.ws?.close()
    this.#i.ws = null
  }
}
