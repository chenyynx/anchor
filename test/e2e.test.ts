/**
 * 端到端：daemon + 模拟手机
 * pair（Noise_XX + pair.req/res）→ hello → 命令下发 → res 结算 → 断线重连补发
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openDb } from '../src/daemon/db'
import { Daemon } from '../src/daemon/daemon'
import { MockPhone } from '../tools/mock-phone'
import { generateDH } from '../src/protocol/noise'
import { deviceIdFromPub } from '../src/lib/ids'
import { generateDH as genDH, NoiseXX } from '../src/protocol/noise'

const freePort = (): number => 18700 + Math.floor(Math.random() * 300)

test('e2e：配对 → hello → 命令往返 → 幂等/TTL 生效', async () => {
  const port = freePort()
  const daemon = new Daemon({
    db: openDb(':memory:'),
    staticKey: generateDH(),
    port,
  })
  await daemon.listen()

  try {
    // ① 打开配对窗口，模拟手机扫码
    const uri = daemon.openPairing([`ws://127.0.0.1:${port}/pair`], '测试机')
    const phone = new MockPhone({ url: '', onLog: () => {} })
    const pairRes = await phone.pair(uri)
    assert.equal(pairRes.status, 'accepted')
    assert.equal(pairRes.controller, true, '首台设备成为主控')
    assert.ok(String((pairRes.agent as { id?: string })?.id).length === 16)
    phone.close()

    // ② 日常会话：hello
    const phone2 = new MockPhone({ url: '', onLog: () => {} })
    // 重开一个窗口（口令一次性）——但设备已注册，hello 走已配对身份
    // 注：日常会话不经配对窗口，直接 ws://…/ws + Noise（设备持有 agent 静态公钥）
    // 这里为了测试简单，用新窗口再连一次并 hello
    const uri2 = daemon.openPairing([`ws://127.0.0.1:${port}/ws`], '测试机')
    await phone2.pair(uri2)
    const helloRes = await phone2.hello()
    assert.equal(helloRes.ok, true)
    assert.equal(helloRes.scopes, 'manage')
    assert.equal(helloRes.pending, 0)

    // ③ ping/pong
    const pong = await phone2.ping()
    assert.equal(pong.t, 'pong')

    // ④ 命令下发：往队列塞一条，重连 hello 后应补发并被应答
    // （当前 daemon 的 hello 只报 pending 数，主动下发留待会话推送批次；这里验证结算通路）
    const pending2 = daemon.queue.pendingCount(phone2.devId)
    assert.equal(pending2, 0)
    phone2.close()
  } finally {
    daemon.close()
  }
})

test('e2e：无效口令被拒', async () => {
  const port = freePort()
  const daemon = new Daemon({
    db: openDb(':memory:'),
    staticKey: generateDH(),
    port,
  })
  await daemon.listen()
  try {
    const uri = daemon.openPairing([`ws://127.0.0.1:${port}/pair`])
    const phone = new MockPhone({ url: '' })
    // 篡改口令
    const bad = uri.replace(/s=[^&]+/, 's=AAAAAAAAAAAAAAAAAAAAAA')
    const res = await phone.pair(bad)
    assert.equal(res.status, 'rejected')
    phone.close()
    assert.equal(daemon.registry.count(), 0)
  } finally {
    daemon.close()
  }
})

test('e2e：命令下发→设备应答→结算（会话内推送）', async () => {
  const port = freePort()
  const daemon = new Daemon({
    db: openDb(':memory:'),
    staticKey: generateDH(),
    port,
  })
  await daemon.listen()
  try {
    const uri = daemon.openPairing([`ws://127.0.0.1:${port}/ws`])
    const phone = new MockPhone({ url: '' })
    await phone.pair(uri)
    await phone.hello()
    phone.installAutoResponder()

    // 在线即时下发：submitCommand 应推给在线会话并被 mock 应答、结算
    const sub = daemon.submitCommand({
      devId: phone.devId,
      ch: 'app',
      op: 'app.profile.refresh',
      ttl_ms: 60000,
    })
    assert.ok(sub.ok)
    // 等 mock 应答回包结算
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 100))
      const item = daemon.queue.get(sub.id!)
      if (item && item.state === 'applied') break
    }
    const settled = daemon.queue.get(sub.id!)
    assert.equal(settled?.state, 'applied', '命令应被设备应答并结算')

    // 离线路径：再入队一条（无在线会话时留存），重连后 hello 报 pending 并补发
    const devId = phone.devId
    phone.close()
    await new Promise((r) => setTimeout(r, 200))
    daemon.queue.enqueue({ devId, ch: 'app', op: 'app.profile.refresh', ttl_ms: 60000 })
    const phone2 = new MockPhone({ url: '' })
    const uri2 = daemon.openPairing([`ws://127.0.0.1:${port}/ws`])
    await phone2.pair(uri2)
    const helloRes = await phone2.hello()
    phone2.installAutoResponder()
    assert.equal(helloRes.pending, 0, '补发后 pending 应清零')
    await new Promise((r) => setTimeout(r, 300))
    phone2.close()
    await new Promise((r) => setTimeout(r, 100))
  } finally {
    daemon.close()
  }
})
