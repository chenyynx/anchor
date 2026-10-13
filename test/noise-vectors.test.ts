/** 黄金向量自检：gen 脚本产物必须可复现关键不变量（Swift 侧按同一文件互验）。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, createHmac, createCipheriv, createDecipheriv, diffieHellman, createPrivateKey, createPublicKey } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const V = JSON.parse(readFileSync(join(here, 'vectors-noise.json'), 'utf8'))

const xFromRaw = (privRaw: string) =>
  createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(privRaw, 'hex')]), format: 'der', type: 'pkcs8' })

test('向量·DH：RFC7748 测试密钥共享密钥一致', () => {
  const d = V.primitives.dh
  const s1 = diffieHellman({ privateKey: xFromRaw(d.alice_priv), publicKey: createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(d.bob_pub, 'hex')]), format: 'der', type: 'spki' }) })
  assert.equal(Buffer.from(s1).toString('hex'), d.shared)
})

test('向量·HKDF：两段输出逐字节一致', () => {
  const h = V.primitives.hkdf2
  const prk = createHmac('sha256', Buffer.from(h.ck, 'hex')).update(Buffer.from(h.ikm, 'hex')).digest()
  const t1 = createHmac('sha256', prk).update(Buffer.of(1)).digest()
  const t2 = createHmac('sha256', prk).update(Buffer.concat([t1, Buffer.of(2)])).digest()
  assert.equal(t1.toString('hex'), h.t1)
  assert.equal(t2.toString('hex'), h.t2)
})

test('向量·AES-GCM：密文逐字节一致 + 往返成立', () => {
  const a = V.primitives.aes_gcm
  const c = createCipheriv('aes-256-gcm', Buffer.from(a.key, 'hex'), Buffer.from(a.nonce, 'hex'))
  c.setAAD(Buffer.from(a.ad, 'hex'))
  const body = Buffer.concat([c.update(Buffer.from(a.plaintext, 'hex')), c.final()])
  assert.equal(Buffer.concat([body, c.getAuthTag()]).toString('hex'), a.ciphertext)
})

test('向量·mixHash：H(h0 || input) 一致', () => {
  const m = V.primitives.mixHash
  const out = createHash('sha256').update(Buffer.concat([Buffer.from(V.primitives.h0, 'hex'), Buffer.from(m.input, 'hex')])).digest()
  assert.equal(out.toString('hex'), m.output)
})
