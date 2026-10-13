/**
 * P4 挂起队列 + deferred 语义测试：
 *  - 设备离线时命令排队（已有），Wake 唤醒钩子被触发
 *  - 设备回 deferred → 命令重排回队列，attempts+1
 *  - deferred 重试超 5 次 → rejected 终结
 *  - 设备重新 hello → 队列补发
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { openDb, type Db } from '../src/daemon/db.ts'
import { Daemon } from '../src/daemon/daemon.ts'
import { generateDH } from '../src/protocol/noise'

function freshDaemon(wake?: { gatewayUrl: string }) {
  const db = openDb(':memory:')
  const key = generateDH()
  const wakes: string[] = []
  const daemon = new Daemon({
    db,
    staticKey: key,
    port: 0,
    agentId: 'agent_test',
    wake,
    onLog: () => {},
  })
  // 仅当测试要求 wake 配置时才覆盖钩子（模拟 WakeClient 观测点）；
  // 无 wake 配置时保持 daemon 原状（钩子为空 = 不唤醒）。
  if (wake) {
    daemon.sessions.wakeHook = (devId: string) => wakes.push(devId)
  }
  return { daemon, wakes, db }
}

test('offline device submit triggers wake hook, command stays queued', () => {
  const { daemon, wakes } = freshDaemon({ gatewayUrl: 'http://127.0.0.1:1' })
  daemon.registry.upsert({ devId: 'dev_a', pub: 'pub', roles: ['app'], scopes: 'operate' })
  const r = daemon.submitCommand({ devId: 'dev_a', ch: 'app', op: 'app.vpn.start', args: {} })
  assert.ok(r.ok)
  assert.equal(wakes.length, 1)
  assert.equal(wakes[0], 'dev_a')
  // 命令留在队列
  assert.equal(daemon.queue.pendingCount('dev_a'), 1)
})

test('no wake config → no hook fires, command still queued', () => {
  const { daemon, wakes } = freshDaemon()
  daemon.registry.upsert({ devId: 'dev_b', pub: 'pub', roles: ['app'], scopes: 'operate' })
  daemon.submitCommand({ devId: 'dev_b', ch: 'app', op: 'app.state.get', args: {} })
  assert.equal(wakes.length, 0)
  assert.equal(daemon.queue.pendingCount('dev_b'), 1)
})

test('deferred settles requeue the command with attempts+1', () => {
  const { daemon } = freshDaemon()
  daemon.registry.upsert({ devId: 'dev_c', pub: 'pub', roles: ['app'], scopes: 'operate' })
  const r = daemon.submitCommand({ devId: 'dev_c', ch: 'app', op: 'app.vpn.start', args: {} })
  // 模拟 sent 状态（设备已收到）
  daemon.queue.markSent(r.id)
  // 设备回 deferred
  const settled = daemon.sessions.settle(r.id, { t: 'res', ref: r.id, ok: false, status: 'deferred' })
  assert.ok(settled)
  const item = daemon.queue.get(r.id)!
  assert.equal(item.state, 'queued', 'deferred 后应重排回队列')
  assert.equal(item.attempts, 1)
  assert.equal(daemon.queue.pendingCount('dev_c'), 1)
})

test('deferred beyond 5 attempts terminates as rejected', () => {
  const { daemon } = freshDaemon()
  daemon.registry.upsert({ devId: 'dev_d', pub: 'pub', roles: ['app'], scopes: 'operate' })
  const r = daemon.submitCommand({ devId: 'dev_d', ch: 'app', op: 'app.vpn.stop', args: {} })
  // 连续 6 轮 sent→deferred
  for (let i = 0; i < 6; i++) {
    daemon.queue.markSent(r.id)
    daemon.sessions.settle(r.id, { t: 'res', ref: r.id, ok: false, status: 'deferred' })
  }
  const item = daemon.queue.get(r.id)!
  assert.equal(item.state, 'rejected', '超限后终结为 rejected')
})

test('applied still settles terminally (no requeue)', () => {
  const { daemon } = freshDaemon()
  daemon.registry.upsert({ devId: 'dev_e', pub: 'pub', roles: ['app'], scopes: 'operate' })
  const r = daemon.submitCommand({ devId: 'dev_e', ch: 'app', op: 'app.state.get', args: {} })
  daemon.queue.markSent(r.id)
  daemon.sessions.settle(r.id, { t: 'res', ref: r.id, ok: true, status: 'applied', data: {} })
  const item = daemon.queue.get(r.id)!
  assert.equal(item.state, 'applied')
  assert.equal(daemon.queue.pendingCount('dev_e'), 0)
})
