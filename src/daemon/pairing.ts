/**
 * 配对窗口：生成一次性口令（pairing URI），等设备来消费。
 *
 * - URI 由 pairing.schema.json#/$defs/pairingURI 约束（k=43 / s=22，base64url）
 * - 真正的 Noise_XX 握手在 WS 层完成；这里只管窗口生命周期 + 口令核对（常量时间）
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { ulid } from '../lib/ids'

export interface PairingWindow {
  id: string
  secret: string
  uri: string
  created_at: number
  /** ms；URI 中 x 字段取其秒值 */
  expires_at: number
}

export const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url')

export const buildPairingURI = (o: {
  k: string
  secret: string
  endpoints: string[]
  name?: string
  /** ms */
  expiresAt: number
}): string => {
  const parts = [
    'v=1',
    `k=${o.k}`,
    `s=${o.secret}`,
    `e=${o.endpoints.map((ep) => encodeURIComponent(ep)).join(',')}`,
  ]
  if (o.name) parts.push(`n=${encodeURIComponent(o.name)}`)
  parts.push(`x=${Math.floor(o.expiresAt / 1000)}`)
  return `hako://pair?${parts.join('&')}`
}

const safeEqual = (a: string, b: string): boolean =>
  timingSafeEqual(
    createHash('sha256').update(a).digest(),
    createHash('sha256').update(b).digest(),
  )

export class PairingWindows {
  #windows: PairingWindow[] = []
  readonly ttlSec: number
  readonly max: number

  constructor(opts: { ttlSec?: number; max?: number } = {}) {
    this.ttlSec = opts.ttlSec ?? 120
    this.max = opts.max ?? 8
  }

  open(
    o: { k: string; endpoints: string[]; name?: string },
    now = Date.now(),
  ): PairingWindow {
    this.sweep(now)
    if (this.#windows.length >= this.max) {
      throw Object.assign(new Error('同时打开的配对窗口过多'), { code: 'RATE_LIMITED' })
    }
    const secret = b64url(randomBytes(16))
    const expires_at = now + this.ttlSec * 1000
    const uri = buildPairingURI({
      k: o.k,
      secret,
      endpoints: o.endpoints,
      name: o.name,
      expiresAt: expires_at,
    })
    const w: PairingWindow = { id: ulid(now), secret, uri, created_at: now, expires_at }
    this.#windows.push(w)
    return w
  }

  verify(secret: string, now = Date.now()): PairingWindow | undefined {
    this.sweep(now)
    return this.#windows.find((w) => safeEqual(w.secret, secret))
  }

  /** 一次性消费：核对成功即移除 */
  consume(secret: string, now = Date.now()): PairingWindow | undefined {
    const w = this.verify(secret, now)
    if (w) this.#windows = this.#windows.filter((x) => x !== w)
    return w
  }

  /** 清理过期窗口，返回清理条数 */
  sweep(now = Date.now()): number {
    const before = this.#windows.length
    this.#windows = this.#windows.filter((w) => w.expires_at > now)
    return before - this.#windows.length
  }

  active(now = Date.now()): PairingWindow[] {
    this.sweep(now)
    return [...this.#windows]
  }
}
