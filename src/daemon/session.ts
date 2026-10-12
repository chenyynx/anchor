/**
 * WebSocket 会话层：每条连接一个 WireSession（响应方视角，agent 恒为 responder）。
 *
 * 帧约定（与 noise.ts 一致）：
 *   - 握手：3 条 WS binary 消息（msg1=32B / msg2=re(32)||ct(48)||ct / msg3=ct(48)||ct）
 *   - 传输：每条 WS binary 消息 = noise 传输帧（2B 大端长度 + AES-GCM 密文）
 *   - 明文：UTF-8 JSON（envelope.schema.json 的帧）
 */
import type { WebSocket as WsSocket } from 'ws'
import type { NoiseXX } from '../protocol/noise'

export interface SessionEvents {
  onJSON: (msg: Record<string, unknown>, session: WireSession) => void
  onClose: (session: WireSession) => void
  onError: (e: Error, session: WireSession) => void
  /** Noise 握手完成，拿到对端静态公钥 */
  onHandshake: (remoteStatic: Buffer, session: WireSession) => void
}

export interface WireSession {
  readonly id: string
  readonly noise: NoiseXX
  closed: boolean
  send(obj: Record<string, unknown>): void
  sendRaw(buf: Buffer): void
  close(code?: number): void
}

export const createResponderSession = (
  ws: WsSocket,
  o: { id: string; noise: NoiseXX; events: SessionEvents },
): WireSession => {
  let hsStage: 0 | 1 | 2 = 0

  const s: WireSession = {
    id: o.id,
    noise: o.noise,
    closed: false,
    send(obj): void {
      if (s.closed) return
      s.sendRaw(o.noise.send(Buffer.from(JSON.stringify(obj), 'utf8')))
    },
    sendRaw(buf): void {
      if (!s.closed) ws.send(buf, { binary: true })
    },
    close(code = 1000): void {
      s.closed = true
      try {
        ws.close(code)
      } catch {
        /* already closing */
      }
    },
  }

  ws.on('message', (data: Buffer, isBinary: boolean) => {
    if (s.closed) return
    try {
      if (!isBinary) throw new Error('noise: 仅接受二进制帧')
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer)

      if (!o.noise.handshakeComplete) {
        if (hsStage === 0) {
          o.noise.readMsg1(buf)
          s.sendRaw(o.noise.writeMsg2())
          hsStage = 1
        } else {
          const payload = o.noise.readMsg3(buf)
          hsStage = 2
          o.events.onHandshake(o.noise.remoteStatic!, s)
          if (payload.length > 0) {
            o.events.onJSON(JSON.parse(payload.toString('utf8')), s)
          }
        }
        return
      }

      const pt = o.noise.recv(buf)
      o.events.onJSON(JSON.parse(pt.toString('utf8')), s)
    } catch (e) {
      o.events.onError(e as Error, s)
    }
  })

  ws.on('close', () => {
    if (!s.closed) {
      s.closed = true
      o.events.onClose(s)
    }
  })
  ws.on('error', (e: Error) => {
    if (!s.closed) o.events.onError(e, s)
  })

  return s
}
