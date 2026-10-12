/**
 * agent 端身份：Ed25519（签名/凭证）+ X25519（Noise 静态密钥）。
 *
 * - 落盘 <home>/identity.json（0600），home 默认 ~/.anchor（可用 ANCHOR_HOME 覆盖）
 * - agent_id = Ed25519 公钥哈希派生（见 lib/ids.ts），加载时校验一致性
 * - 配对 URI 里的 k = X25519 公钥原文的 base64url（43 字符）
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { agentIdFromPub } from '../lib/ids'

export interface IdentityFile {
  v: 1
  agent_id: string
  created_at: number
  keys: {
    ed25519: { private_pem: string; public_pem: string }
    x25519: { private_pem: string; public_pem: string }
  }
}

export interface Identity {
  readonly agentId: string
  readonly created_at: number
  /** Ed25519 公钥原文（32B） */
  readonly edPubRaw: Buffer
  /** X25519 静态公钥原文（32B，配对 URI 的 k） */
  readonly xPubRaw: Buffer
  sign(data: Uint8Array): Buffer
  verify(data: Uint8Array, sig: Uint8Array): boolean
  toFile(): IdentityFile
}

const rawPub = (key: KeyObject): Buffer =>
  key.export({ type: 'spki', format: 'der' }).subarray(-32)

const pem = (key: KeyObject, type: 'pkcs8' | 'spki'): string =>
  key.export({ type, format: 'pem' }).toString()

const makeIdentity = (file: IdentityFile): Identity => {
  const edPriv = createPrivateKey(file.keys.ed25519.private_pem)
  const edPub = createPublicKey(edPriv)
  const xPriv = createPrivateKey(file.keys.x25519.private_pem)
  const xPub = createPublicKey(xPriv)

  const edPubRaw = rawPub(edPub)
  const agentId = agentIdFromPub(edPubRaw)
  if (file.agent_id !== agentId) {
    throw Object.assign(new Error('identity: agent_id 与公钥不匹配（文件被篡改或损坏）'), {
      code: 'KEY_MISMATCH',
    })
  }

  return {
    agentId,
    created_at: file.created_at,
    edPubRaw,
    xPubRaw: rawPub(xPub),
    sign: (data) => edSign(null, Buffer.from(data), edPriv),
    verify: (data, sig) => {
      try {
        return edVerify(null, Buffer.from(data), edPub, Buffer.from(sig))
      } catch {
        return false
      }
    },
    toFile: () => file,
  }
}

export const identityPath = (home: string): string => join(home, 'identity.json')

/** 生成全新身份（不落盘） */
export const createIdentity = (now = Date.now()): Identity => {
  const ed = generateKeyPairSync('ed25519')
  const x = generateKeyPairSync('x25519')
  const file: IdentityFile = {
    v: 1,
    agent_id: agentIdFromPub(rawPub(ed.publicKey)),
    created_at: now,
    keys: {
      ed25519: { private_pem: pem(ed.privateKey, 'pkcs8'), public_pem: pem(ed.publicKey, 'spki') },
      x25519: { private_pem: pem(x.privateKey, 'pkcs8'), public_pem: pem(x.publicKey, 'spki') },
    },
  }
  return makeIdentity(file)
}

export const parseIdentityFile = (json: string): Identity =>
  makeIdentity(JSON.parse(json) as IdentityFile)

export const loadIdentity = (home: string): Identity =>
  parseIdentityFile(readFileSync(identityPath(home), 'utf8'))

export const saveIdentity = (home: string, ident: Identity): string => {
  mkdirSync(home, { recursive: true, mode: 0o700 })
  const p = identityPath(home)
  const tmp = `${p}.tmp`
  writeFileSync(tmp, `${JSON.stringify(ident.toFile(), null, 2)}\n`, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, p)
  chmodSync(p, 0o600)
  return p
}

export const loadOrCreateIdentity = (
  home: string,
  now = Date.now(),
): { ident: Identity; created: boolean } => {
  if (existsSync(identityPath(home))) {
    return { ident: loadIdentity(home), created: false }
  }
  const ident = createIdentity(now)
  saveIdentity(home, ident)
  return { ident, created: true }
}
