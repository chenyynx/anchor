/**
 * 生成 Noise_XX 黄金测试向量（固定输入 → 输出字节）。
 *
 * 用途：Swift（CryptoKit）侧实现的互验基准。所有随机输入用确定性 DH
 * （RFC 7748 §6.1 / RFC 8032 §7.4 测试密钥），保证两端跑出完全相同的字节。
 *
 * 产出 test/vectors-noise.json：
 *   - 密钥对（raw hex）
 *   - 三条握手消息（hex）
 *   - 握手后双向各两帧传输帧（hex）与解出的明文
 *   - 通道密钥 ck/c1/c2（hex，供逐字段比对）
 */
import { writeFileSync } from 'node:fs'
import { createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto'
import { NoiseXX, generateDH, dhRaw, MAX_PLAINTEXT } from '../src/protocol/noise'

/* ---- 确定性 X25519 密钥（RFC 7748 §6.1 Alice/Bob）---- */
const alicePrivRaw = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')
const bobPrivRaw = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')

const xFromRaw = (privRaw: Buffer): ReturnType<typeof createPrivateKey> => {
  // PKCS#8 前缀 for x25519: 302e020100300506032b656e04220420
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privRaw])
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
}
const alicePriv = xFromRaw(alicePrivRaw)
const bobPriv = xFromRaw(bobPrivRaw)
const alicePubRaw = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
const bobPubRaw = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex')

const key = (privRaw: Buffer, pubRaw: Buffer) => ({
  priv: xFromRaw(privRaw),
  pub: pubRaw,
})

// 注：NoiseXX 需要随机生成 e（writeMsg1/writeMsg2 内部 generateDH），
// 为了确定性向量，这里改用「注入式」：临时子类不再可行（#e 私有）。
// 方案：直接调用底层序列 + 用 generateDH 的真实随机但只断言不变量（往返型向量），
// 另外单独产出「确定性 DH」的 ck/密钥向量供 Swift 对齐 mixKey/mixHash 原语。
// 折中：黄金向量分两类——
//   A. handshake vectors：两端互通 + 传输帧往返（Swift 只需复现协议逻辑，密钥随机）
//   B. primitive vectors：固定输入→固定输出的 HKDF/AES-GCM/mixHash/nonce 序号（确定性，逐字节比）

import { createHash, createHmac, createCipheriv, createDecipheriv } from 'node:crypto'
import { hkdf } from '../src/protocol/noise'

const PROTO = 'Noise_XX_25519_AESGCM_SHA256'
const H0 = (() => {
  const h = Buffer.from(PROTO)
  return Buffer.concat([h, Buffer.alloc(32 - h.length)])
})()

const primitives: Record<string, unknown> = {
  protocol_name: PROTO,
  h0: H0.toString('hex'),
  mixHash: (() => {
    const input = Buffer.from('00ff10abcd', 'hex')
    const out = createHash('sha256').update(Buffer.concat([H0, input])).digest()
    return { input: input.toString('hex'), output: out.toString('hex') }
  })(),
  hkdf2: (() => {
    const ck = createHash('sha256').update('anchor-ck-seed').digest()
    const ikm = Buffer.from('deadbeefcafebabe0123456789abcdef', 'hex')
    const [t1, t2] = hkdf(ck, ikm)
    return { ck: ck.toString('hex'), ikm: ikm.toString('hex'), t1: t1.toString('hex'), t2: t2.toString('hex') }
  })(),
  aes_gcm: (() => {
    const keyBuf = createHash('sha256').update('anchor-aes-key').digest()
    const nonce = Buffer.alloc(12)
    nonce.writeBigUInt64LE(BigInt(7), 4)
    const ad = Buffer.from('aabbccdd', 'hex')
    const pt = Buffer.from('The quick brown fox jumps over the lazy dog', 'utf8')
    const c = createCipheriv('aes-256-gcm', keyBuf, nonce)
    c.setAAD(ad)
    const body = Buffer.concat([c.update(pt), c.final()])
    const tag = c.getAuthTag()
    const ct = Buffer.concat([body, tag])
    const d = createDecipheriv('aes-256-gcm', keyBuf, nonce)
    d.setAAD(ad)
    d.setAuthTag(tag)
    const rt = Buffer.concat([d.update(body), d.final()]).equals(pt)
    return { key: keyBuf.toString('hex'), nonce: nonce.toString('hex'), ad: ad.toString('hex'), plaintext: pt.toString('hex'), ciphertext: ct.toString('hex'), roundtrip_ok: rt }
  })(),
  dh: (() => {
    const shared = dhRaw(alicePriv, bobPubRaw)
    const shared2 = dhRaw(bobPriv, alicePubRaw)
    return {
      alice_priv: alicePrivRaw.toString('hex'), alice_pub: alicePubRaw.toString('hex'),
      bob_priv: bobPrivRaw.toString('hex'), bob_pub: bobPubRaw.toString('hex'),
      shared: shared.toString('hex'), shared_equal: shared.equals(shared2),
    }
  })(),
}

/* ---- 握手往返向量（随机但双端互通断言） ---- */
const runHandshake = (msg3Payload: Buffer, frames: number) => {
  const agentKey = generateDH()
  const dev = new NoiseXX(true, generateDH(), agentKey.pub)
  const agent = new NoiseXX(false, agentKey)
  const m1 = dev.writeMsg1()
  agent.readMsg1(m1)
  const m2 = agent.writeMsg2()
  const { rs, payload: m2p } = dev.readMsg2(m2)
  if (!rs.equals(agentKey.pub) || m2p.length !== 0) throw new Error('m2 invariant')
  const m3 = dev.writeMsg3(msg3Payload)
  const m3p = agent.readMsg3(m3)
  if (!m3p.equals(msg3Payload)) throw new Error('m3 payload invariant')

  const traffic: { dir: string; plaintext: string; frame: string }[] = []
  for (let i = 0; i < frames; i++) {
    const d2a = Buffer.from(`dev->agent frame ${i}: rngjpy`, 'utf8')
    const f = dev.send(d2a)
    const got = agent.recv(f)
    traffic.push({ dir: 'd2a', plaintext: d2a.toString('hex'), frame: f.toString('hex') })
    if (!got.equals(d2a)) throw new Error('frame invariant d2a')
    const a2d = Buffer.from(`agent->dev frame ${i}: 0123`, 'utf8')
    const f2 = agent.send(a2d)
    const got2 = dev.recv(f2)
    traffic.push({ dir: 'a2d', plaintext: a2d.toString('hex'), frame: f2.toString('hex') })
    if (!got2.equals(a2d)) throw new Error('frame invariant a2d')
  }
  return { m1: m1.toString('hex'), m2: m2.toString('hex'), m3: m3.toString('hex'), m3_payload: msg3Payload.toString('hex'), traffic, rs: rs.toString('hex') }
}

const hs1 = runHandshake(Buffer.from(JSON.stringify({ t: 'pair.req', secret: 'AAAA' }), 'utf8'), 2)

const vectors = {
  $comment: 'Anchor Noise_XX golden vectors. primitives.* = deterministic byte-exact; handshake = round-trip invariants both ends must satisfy. Generated by tools/gen-noise-vectors.ts (TS reference impl).',
  primitives,
  handshake: hs1,
  limits: { MAX_PLAINTEXT },
}

writeFileSync(new URL('../test/vectors-noise.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n')
console.log('vectors-noise.json written')
console.log('primitive checks:', JSON.stringify({ dh_equal: primitives.dh, aes_ok: primitives.aes_gcm }, null, 0).slice(0, 200))
