import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openDb } from '../src/daemon/db'
import { OutboundQueue } from '../src/daemon/queue'

const mk = () => new OutboundQueue(openDb(':memory:'))
const DEV = 'dev_0000000000000001'
const DEV2 = 'dev_0000000000000002'

test('queue：入队 / 先进先出 / 序号单调 / 结算', () => {
  const q = mk()
  const a = q.enqueue({ devId: DEV, ch: 'app', op: 'app.profile.select', args: { id: 'p1' } }, 1000)
  assert.ok(a.ok)
  assert.equal(a.item.state, 'queued')
  const b = q.enqueue({ devId: DEV, ch: 'ext', op: 'core.mode.set', args: { mode: 'rule' } }, 1001)
  assert.ok(b.ok)

  const first = q.next(DEV)
  assert.equal(first?.id, a.item.id, '先进先出')
  const sent1 = q.markSent(first!.id, 1002)
  assert.equal(sent1?.state, 'sent')
  assert.equal(sent1?.seq, 1)
  assert.equal(sent1?.attempts, 1)

  const sent2 = q.markSent(q.next(DEV)!.id, 1003)
  assert.equal(sent2?.seq, 2, '每设备序号单调')

  const settled = q.settle(sent1!.id, { ok: true, status: 'applied', data: { rev: 7 } }, 1004)
  assert.equal(settled?.state, 'applied')
  assert.deepEqual(settled?.result, { rev: 7 })
  assert.equal(q.settle(sent1!.id, { ok: true, status: 'applied' }), null, '已结算不可重复结算')
})

test('queue：幂等键去重（同设备）', () => {
  const q = mk()
  const first = q.enqueue({ devId: DEV, ch: 'app', op: 'app.vpn.start', idem: 'k1' }, 1000)
  const dup = q.enqueue({ devId: DEV, ch: 'app', op: 'app.vpn.start', idem: 'k1' }, 2000)
  assert.ok(first.ok)
  assert.equal(dup.ok, false)
  assert.equal(dup.duplicate, true)
  assert.equal(dup.item.id, first.item.id, '重复入队返回既有条目')
})

test('queue：幂等键每设备独立', () => {
  const q = mk()
  q.enqueue({ devId: DEV, ch: 'app', op: 'a.b', idem: 'k1' }, 1000)
  const other = q.enqueue({ devId: DEV2, ch: 'app', op: 'a.b', idem: 'k1' }, 1000)
  assert.ok(other.ok, '不同设备的同幂等键互不影响')
})

test('queue：TTL 过期清扫 + pendingCount', () => {
  const q = mk()
  const a = q.enqueue({ devId: DEV, ch: 'app', op: 'a.b', ttl_ms: 1000 }, 0)
  q.enqueue({ devId: DEV, ch: 'app', op: 'c.d', ttl_ms: 60000 }, 0)
  assert.equal(q.pendingCount(DEV), 2)
  const n = q.expire(1001)
  assert.equal(n, 1, '仅超 TTL 的一条被清扫')
  assert.equal(q.get(a.item.id)?.state, 'expired')
  assert.equal(q.pendingCount(DEV), 1)
})

test('queue：重发不换号、attempts 递增', () => {
  const q = mk()
  const a = q.enqueue({ devId: DEV, ch: 'ext', op: 'core.probe' }, 0)
  const s1 = q.markSent(a.item.id, 1)
  const s2 = q.markSent(a.item.id, 2)
  assert.equal(s2?.seq, s1?.seq)
  assert.equal(s2?.attempts, 2)
})

test('queue：结算 rejected 与 err 持久化', () => {
  const q = mk()
  const a = q.enqueue({ devId: DEV, ch: 'app', op: 'app.vpn.start' }, 0)
  q.markSent(a.item.id, 1)
  const s = q.settle(
    a.item.id,
    { ok: false, status: 'rejected', err: { code: 'NEED_USER_ACTION', message: '需要允许 VPN' } },
    2,
  )
  assert.equal(s?.state, 'rejected')
  assert.equal((s?.err as { code: string }).code, 'NEED_USER_ACTION')
})
