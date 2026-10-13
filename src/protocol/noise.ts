/**
 * Noise_XX 握手 + 传输加密（手写，只用 node:crypto 原生原语）。
 *
 * - 协议名 Noise_XX_25519_AESGCM_SHA256（与方案 v4 §安全 一致）
 * - X25519 / HKDF-SHA256 / AES-256-GCM
 * - 传输帧：2 字节大端长度 + AES-GCM 密文（单帧明文 ≤ 65535-16）
 * - Swift 侧（CryptoKit）按同一规范实现，靠共享测试向量互验
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto'

export const PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256'
export const DHLEN = 32
export const MAX_FRAME = 65535
/** 传输帧明文上限（扣掉 GCM 16B tag） */
export const MAX_PLAINTEXT = MAX_FRAME - 16

/* ---------------- 基础件 ---------------- */

export const hkdf = (ck: Buffer, ikm: Buffer, outLen = 2): Buffer[] => {
  const salt = ck.length === 32 ? ck : Buffer.alloc(32, 0)
  const prk = createHmac('sha256', salt).update(ikm).digest()
  const outs: Buffer[] = []
  let prev = Buffer.alloc(0)
  for (let i = 1; i <= outLen; i++) {
    prev = Buffer.from(
      createHmac('sha256', prk)
        .update(Buffer.concat([prev, Buffer.alloc(0)]))
        .update(Buffer.of(i))
        .digest(),
    )
    outs.push(prev)
  }
  return outs
}

const nonceOf = (n: number): Buffer => {
  const b = Buffer.alloc(12)
  b.writeBigUInt64LE(BigInt(n), 4)
  return b
}

/** 单密钥状态：AES-256-GCM，nonce 从 0 单调递增 */
export class CipherState {
  #key: Buffer | null = null
  #n = 0

  initializeKey(key: Buffer | null): void {
    this.#key = key
    this.#n = 0
  }

  get hasKey(): boolean {
    return this.#key !== null
  }

  encryptWithAd(ad: Buffer, plaintext: Buffer): Buffer {
    if (!this.#key) return plaintext
    if (this.#n >= 2 ** 64 - 1) throw new Error('noise: nonce exhausted')
    const c = createCipheriv('aes-256-gcm', this.#key, nonceOf(this.#n))
    c.setAAD(ad)
    const out = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()])
    this.#n++
    return out
  }

  decryptWithAd(ad: Buffer, ciphertext: Buffer): Buffer {
    if (!this.#key) return ciphertext
    if (ciphertext.length < 16) throw new Error('noise: frame too short')
    const tag = ciphertext.subarray(ciphertext.length - 16)
    const body = ciphertext.subarray(0, ciphertext.length - 16)
    const d = createDecipheriv('aes-256-gcm', this.#key, nonceOf(this.#n))
    d.setAAD(ad)
    d.setAuthTag(tag)
    const out = Buffer.concat([d.update(body), d.final()])
    this.#n++
    return out
  }
}

class SymmetricState {
  cs = new CipherState()
  ck = Buffer.alloc(0)
  h = Buffer.alloc(0)

  initialize(): void {
    this.h = Buffer.from(PROTOCOL_NAME, 'utf8')
    if (this.h.length < 32) {
      this.h = Buffer.concat([this.h, Buffer.alloc(32 - this.h.length)])
    }
    this.ck = this.h
  }

  mixKey(ikm: Buffer): void {
    const [newCk, tempK] = hkdf(this.ck, ikm)
    this.ck = Buffer.from(newCk)
    this.cs.initializeKey(Buffer.from(tempK))
  }

  mixHash(data: Buffer): void {
    this.h = createHash('sha256').update(Buffer.concat([this.h, data])).digest()
  }

  encryptAndHash(plaintext: Buffer): Buffer {
    const ct = this.cs.encryptWithAd(this.h, plaintext)
    this.mixHash(ct)
    return ct
  }

  decryptAndHash(ciphertext: Buffer): Buffer {
    const pt = this.cs.decryptWithAd(this.h, ciphertext)
    this.mixHash(ciphertext)
    return pt
  }

  split(): { c1: CipherState; c2: CipherState } {
    const [t1, t2] = hkdf(this.ck, Buffer.alloc(0))
    const c1 = new CipherState()
    const c2 = new CipherState()
    c1.initializeKey(Buffer.from(t1))
    c2.initializeKey(Buffer.from(t2))
    return { c1, c2 }
  }
}

/* ---------------- X25519 工具 ---------------- */

export interface DHKey {
  priv: KeyObject
  pub: Buffer
}

export const generateDH = (): DHKey => {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  return { priv: privateKey, pub: rawPublic(publicKey) }
}

export const rawPublic = (key: KeyObject): Buffer =>
  key.export({ type: 'spki', format: 'der' }).subarray(-32)

export const dhRaw = (priv: KeyObject, peerPubRaw: Buffer): Buffer =>
  diffieHellman({
    privateKey: priv,
    publicKey: fromRawPublic(peerPubRaw),
  })

export const fromRawPublic = (raw: Buffer): KeyObject => {
  const prefix = Buffer.from('302a300506032b656e032100', 'hex')
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' })
}

/* ---------------- Noise_XX 握手 ---------------- */

const EMPTY = Buffer.alloc(0)

/**
 * XX 握手（3 消息）：
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 * 发起方 = 设备（持有 agent 静态公钥），响应方 = agent。
 */
export class NoiseXX {
  #ss = new SymmetricState()
  #initiator: boolean
  #s: DHKey
  #e: DHKey | null = null
  #re: Buffer | null = null
  #rs: Buffer | null = null
  #stage = 0
  #send: CipherState | null = null
  #recv: CipherState | null = null

  constructor(initiator: boolean, staticKey: DHKey, remoteStatic?: Buffer) {
    this.#initiator = initiator
    this.#s = staticKey
    if (initiator && remoteStatic) this.#rs = remoteStatic
    this.#ss.initialize()
  }

  get remoteStatic(): Buffer | null {
    return this.#rs
  }

  get handshakeComplete(): boolean {
    return this.#stage >= 3
  }

  /* --- 发起方 --- */

  writeMsg1(): Buffer {
    this.#assertInitiator()
    if (this.#stage !== 0) throw new Error('noise: msg1 只能是第一条')
    this.#e = generateDH()
    this.#ss.mixHash(this.#e.pub)
    this.#stage = 1
    return this.#e.pub
  }

  readMsg2(msg: Buffer): { rs: Buffer; payload: Buffer } {
    this.#assertInitiator()
    if (this.#stage !== 1) throw new Error('noise: 状态错，期待写 msg1')
    if (msg.length < DHLEN) throw new Error('noise: msg2 太短')
    this.#re = msg.subarray(0, DHLEN)
    this.#ss.mixHash(this.#re)
    // ee
    this.#ss.mixKey(dhRaw(this.#e!.priv, this.#re))
    // s, es：msg2 = re(32) || ct(rs)(48) || ct(payload)，解出对端静态后再 mixKey es
    const rsCt = msg.subarray(DHLEN, DHLEN + DHLEN + 16)
    this.#rs = this.#ss.decryptAndHash(rsCt)
    this.#ss.mixKey(dhRaw(this.#e!.priv, this.#rs))
    // es 之后剩余部分 = msg2 载荷（握手密钥加密）
    const payload = this.#ss.decryptAndHash(msg.subarray(DHLEN + DHLEN + 16))
    this.#stage = 2
    return { rs: this.#rs, payload }
  }

  writeMsg3(payload: Buffer = EMPTY): Buffer {
    this.#assertInitiator()
    if (this.#stage !== 2) throw new Error('noise: 状态错，期待读 msg2')
    const ct = this.#ss.encryptAndHash(this.#s.pub)
    // se
    this.#ss.mixKey(dhRaw(this.#s.priv, this.#re!))
    const payloadCt = this.#ss.encryptAndHash(payload)
    const { c1, c2 } = this.#ss.split()
    this.#send = c1
    this.#recv = c2
    this.#stage = 3
    return Buffer.concat([ct, payloadCt])
  }

  /* --- 响应方 --- */

  readMsg1(msg: Buffer): void {
    this.#assertResponder()
    if (this.#stage !== 0) throw new Error('noise: msg1 只能是第一条')
    if (msg.length !== DHLEN) throw new Error('noise: msg1 应为 32 字节')
    this.#re = msg
    this.#ss.mixHash(this.#re)
    this.#stage = 1
  }

  writeMsg2(payload: Buffer = EMPTY): Buffer {
    this.#assertResponder()
    if (this.#stage !== 1) throw new Error('noise: 状态错，期待读 msg1')
    this.#e = generateDH()
    this.#ss.mixHash(this.#e.pub)
    // ee
    this.#ss.mixKey(dhRaw(this.#e.priv, this.#re!))
    // s, es（先加密自己的静态，再 mixKey es = DH(s_priv, re)）
    const ct = this.#ss.encryptAndHash(this.#s.pub)
    this.#ss.mixKey(dhRaw(this.#s.priv, this.#re!))
    const payloadCt = this.#ss.encryptAndHash(payload)
    this.#stage = 2
    return Buffer.concat([this.#e.pub, ct, payloadCt])
  }

  readMsg3(msg: Buffer): Buffer {
    this.#assertResponder()
    if (this.#stage !== 2) throw new Error('noise: 状态错，期待写 msg2')
    if (msg.length < DHLEN + 16) throw new Error('noise: msg3 太短')
    // msg3 = ct(s.pub)(48) || payload（payload 仍在握手密钥下加密）
    const sCt = msg.subarray(0, DHLEN + 16)
    this.#rs = this.#ss.decryptAndHash(sCt)
    // se = DH(本方临时 e_priv, 对方静态 s_pub)——注意与 es 方向不同
    this.#ss.mixKey(dhRaw(this.#e!.priv, this.#rs))
    const payload = this.#ss.decryptAndHash(msg.subarray(DHLEN + 16))
    const { c1, c2 } = this.#ss.split()
    this.#recv = c1
    this.#send = c2
    this.#stage = 3
    return payload
  }

  /* --- 传输阶段 --- */

  send(plaintext: Buffer): Buffer {
    if (!this.handshakeComplete || !this.#send) throw new Error('noise: 握手未完成')
    if (plaintext.length > MAX_PLAINTEXT) throw new Error('noise: 帧超限')
    const ct = this.#send.encryptWithAd(EMPTY, plaintext)
    const len = Buffer.alloc(2)
    len.writeUInt16BE(ct.length)
    return Buffer.concat([len, ct])
  }

  recv(frame: Buffer): Buffer {
    if (!this.handshakeComplete || !this.#recv) throw new Error('noise: 握手未完成')
    if (frame.length < 2) throw new Error('noise: 帧头缺失')
    const len = frame.readUInt16BE(0)
    if (frame.length - 2 !== len) throw new Error('noise: 帧长度不符')
    return this.#recv.decryptWithAd(EMPTY, frame.subarray(2))
  }

  #assertInitiator(): void {
    if (!this.#initiator) throw new Error('noise: 响应方不能调用发起方方法')
  }

  #assertResponder(): void {
    if (this.#initiator) throw new Error('noise: 发起方不能调用响应方方法')
  }
}
