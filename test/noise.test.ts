/**
 * Noise_XX 契约测试：双端握手互通 + 传输帧往返 + 篡改检测。
 * 这些向量同时构成 Swift（CryptoKit）侧实现的对齐目标。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DHLEN,
  MAX_PLAINTEXT,
  NoiseXX,
  PROTOCOL_NAME,
  dhRaw,
  fromRawPublic,
  generateDH,
  rawPublic,
} from '../src/protocol/noise'

const handshake = () => {
  const agentKey = generateDH()
  const devKey = generateDH()
  const dev = new NoiseXX(true, devKey, agentKey.pub) // 发起方，已知 agent 静态
  const agent = new NoiseXX(false, agentKey)

  const m1 = dev.writeMsg1()
  assert.equal(m1.length, DHLEN)
  agent.readMsg1(m1)

  const m2 = agent.writeMsg2()
  const { rs: agentPubSeen, payload: m2Payload } = dev.readMsg2(m2)
  assert.deepEqual(agentPubSeen, agentKey.pub, '发起方应验证出 agent 静态公钥')
  assert.equal(m2Payload.length, 0, 'msg2 无载荷时返回空')

  const payload = Buffer.from('pair-payload')
  const m3 = dev.writeMsg3(payload)
  const agentGot = agent.readMsg3(m3)
  assert.deepEqual(agentGot, payload, '响应方应解出 msg3 载荷')

  assert.ok(dev.handshakeComplete && agent.handshakeComplete)
  assert.deepEqual(dev.remoteStatic, agentKey.pub)

  return { dev, agent }
}

test('noise：XX 握手三消息互通', handshake)

test('noise：传输阶段双向加解密往返', () => {
  const { dev, agent } = handshake()
  const a2b = dev.send(Buffer.from('hello agent'))
  assert.deepEqual(agent.recv(a2b), Buffer.from('hello agent'))
  const b2a = agent.send(Buffer.from('hi device'))
  assert.deepEqual(dev.recv(b2a), Buffer.from('hi device'))
})

test('noise：密钥方向性（四个方向各自独立）', () => {
  const { dev, agent } = handshake()
  // dev.send 只能被 agent.recv 解；agent.send 只能被 dev.recv 解
  const a2b = dev.send(Buffer.from('x'))
  assert.deepEqual(agent.recv(a2b), Buffer.from('x'))
  const b2a = agent.send(Buffer.from('y'))
  assert.deepEqual(dev.recv(b2a), Buffer.from('y'))
  // 帧不能被发送方自己解（发送/接收密钥不同）
  assert.throws(() => dev.recv(dev.send(Buffer.from('z'))))
  assert.throws(() => agent.recv(agent.send(Buffer.from('z'))))
})

test('noise：密文篡改被 GCM 拒绝', () => {
  const { dev, agent } = handshake()
  const frame = dev.send(Buffer.from('secret'))
  frame[frame.length - 1] ^= 0x01
  assert.throws(() => agent.recv(frame), /Authentication|auth|fail|bad decrypt|did not/i)
})

test('noise：帧长度不匹配被拒（防截断/拼接）', () => {
  const { dev, agent } = handshake()
  const frame = dev.send(Buffer.from('secret'))
  const truncated = frame.subarray(0, frame.length - 1)
  assert.throws(() => agent.recv(truncated))
})

test('noise：明文超过单帧上限被拒', () => {
  const { dev } = handshake()
  assert.throws(() => dev.send(Buffer.alloc(MAX_PLAINTEXT + 1)))
  assert.equal(dev.send(Buffer.alloc(MAX_PLAINTEXT)).length, MAX_PLAINTEXT + 18)
})

test('noise：错误角色的方法互斥', () => {
  const k = generateDH()
  const dev = new NoiseXX(true, k)
  const agent = new NoiseXX(false, k)
  assert.throws(() => agent.writeMsg1())
  assert.throws(() => dev.readMsg1(Buffer.alloc(32)))
})

test('noise：错序握手被拒', () => {
  const agentKey = generateDH()
  const dev = new NoiseXX(true, generateDH(), agentKey.pub)
  const agent = new NoiseXX(false, agentKey)
  assert.throws(() => dev.writeMsg3(), /msg1|状态/)
  assert.throws(() => agent.readMsg3(Buffer.alloc(80)), /msg1|状态/)
})

test('noise：DH 原语自查（双方 DH 相等 + 原始公钥可复原）', () => {
  const a = generateDH()
  const b = generateDH()
  const ab = dhRaw(a.priv, b.pub)
  const ba = dhRaw(b.priv, a.pub)
  assert.deepEqual(ab, ba)
  assert.deepEqual(rawPublic(fromRawPublic(b.pub)), b.pub)
  assert.equal(PROTOCOL_NAME, 'Noise_XX_25519_AESGCM_SHA256')
})
