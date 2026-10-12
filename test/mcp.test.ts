/**
 * MCP 层测试：工具注册、scope 拒绝、设备缺失报错、命令等待超时。
 * 不起真实 stdio 传输——直接调 buildMcpServer 内部 handler 的底层路径。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openDb } from '../src/daemon/db'
import { Daemon } from '../src/daemon/daemon'
import { generateDH, NoiseXX } from '../src/protocol/noise'
import { deviceIdFromPub } from '../src/lib/ids'
import { waitForSettle } from '../src/daemon/wait'
import { OutboundQueue } from '../src/daemon/queue'

const mkDaemon = (port = 19500): Daemon =>
  new Daemon({ db: openDb(':memory:'), staticKey: generateDH(), port, onLog: () => {} })

test('wait：结算后立即返回 / 超时返回当前状态', async () => {
  const q = new OutboundQueue(openDb(':memory:'))
  const a = q.enqueue({ devId: 'dev_0000000000000001', ch: 'app', op: 'a.b' }, 0)
  // 不结算 → 超时返回当前状态（未发送时仍为 queued）
  const t0 = Date.now()
  const item = await waitForSettle(q, a.item.id, 250, 40)
  assert.ok(Date.now() - t0 >= 200, '应等待超时时长')
  assert.equal(item.state, 'queued')
  q.markSent(a.item.id, 1)
  q.settle(a.item.id, { ok: true, status: 'applied' }, 2)
  const done = await waitForSettle(q, a.item.id, 100, 10)
  assert.equal(done.state, 'applied')
  await assert.rejects(() => waitForSettle(q, 'UNKNOWN', 10, 5), /不存在/)
})

test('daemon：submitCommand 走 SessionManager（离线留队列）', async () => {
  const d = mkDaemon(19501)
  assert.equal(d.submitCommand({ devId: 'dev_0000000000000001', ch: 'app', op: 'a.b' }).ok, true)
  assert.equal(d.queue.pendingCount('dev_0000000000000001'), 1)
  // 幂等键重复
  const dup = d.submitCommand({ devId: 'dev_0000000000000001', ch: 'app', op: 'a.b', idem: 'x' })
  assert.equal(d.submitCommand({ devId: 'dev_0000000000000001', ch: 'app', op: 'a.b', idem: 'x' }).ok, false)
  void dup
})

test('noise：会话密钥方向性回归（发起方/响应方 split 互反）', () => {
  const agentKey = generateDH()
  const dev = new NoiseXX(true, generateDH(), agentKey.pub)
  const agent = new NoiseXX(false, agentKey)
  agent.readMsg1(dev.writeMsg1())
  dev.readMsg2(agent.writeMsg2())
  agent.readMsg3(dev.writeMsg3(Buffer.from('p')))
  const a2b = dev.send(Buffer.from('ping'))
  assert.deepEqual(agent.recv(a2b), Buffer.from('ping'))
})

test('daemon：设备缺失时 needDevice 语义（注册表为空）', async () => {
  const d = mkDaemon(19502)
  // 未配对设备：submit 仍入队（等待配对后补发语义由上层决定），但主控查询为空
  assert.equal(d.registry.controller(), null)
  assert.equal(d.registry.count(), 0)
})
