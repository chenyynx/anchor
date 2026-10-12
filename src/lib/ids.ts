/**
 * ID 工具：Crockford Base32 / ULID / agent_id / dev_id
 *
 * - ULID：48 位毫秒时间戳 + 80 位随机 → 26 字符（envelope.id 的 pattern）
 * - agent_id：Ed25519 公钥 SHA-256 前 10 字节 → 16 字符（80 位）
 * - dev_id：同法派生，加 "dev_" 前缀（pairing.schema.json 约束）
 */
import { createHash, randomBytes } from 'node:crypto'

export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/
export const AGENT_ID_RE = /^[0-9A-Z]{16}$/
export const DEV_ID_RE = /^dev_[0-9A-Z]{16}$/

const bytesToBig = (bytes: Uint8Array): bigint => {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

const encodeBig = (value: bigint, chars: number): string => {
  let out = ''
  let v = value
  for (let i = 0; i < chars; i++) {
    out = CROCKFORD[Number(v & 31n)] + out
    v >>= 5n
  }
  if (v !== 0n) throw new Error('crockford: value overflow')
  return out
}

/** 字节串 → Crockford Base32（大端、右对齐、无填充） */
export const crockford = (bytes: Uint8Array): string =>
  encodeBig(bytesToBig(bytes), Math.ceil((bytes.length * 8) / 5))

let lastMs = -1
let lastRand = 0n

/** 生成 ULID；同毫秒内自增保证单调递增 */
export const ulid = (now = Date.now()): string => {
  if (now === lastMs) {
    lastRand = (lastRand + 1n) & ((1n << 80n) - 1n)
  } else {
    lastMs = now
    lastRand = bytesToBig(randomBytes(10))
  }
  const ts = BigInt(now) & ((1n << 48n) - 1n)
  return encodeBig((ts << 80n) | lastRand, 26)
}

/** 公钥原文（Ed25519/X25519 32B）→ 16 字符 id */
export const agentIdFromPub = (pubRaw: Uint8Array): string =>
  crockford(createHash('sha256').update(pubRaw).digest().subarray(0, 10))

export const deviceIdFromPub = (pubRaw: Uint8Array): string => `dev_${agentIdFromPub(pubRaw)}`

export const isUlid = (s: string): boolean => ULID_RE.test(s)
export const isAgentId = (s: string): boolean => AGENT_ID_RE.test(s)
export const isDeviceId = (s: string): boolean => DEV_ID_RE.test(s)
