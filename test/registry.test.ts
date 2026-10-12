import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openDb } from '../src/daemon/db'
import { Registry } from '../src/daemon/registry'

const mk = () => new Registry(openDb(':memory:'))

test('registry：upsert / get / list / count', () => {
  const reg = mk()
  assert.equal(reg.count(), 0)
  const d = reg.upsert({ devId: 'dev_0000000000000001', pub: 'pk1', roles: ['app'], now: 1000 })
  assert.equal(d.created_at, 1000)
  assert.equal(d.last_seen, 1000)
  assert.deepEqual(d.roles, ['app'])
  assert.equal(d.scopes, 'operate')
  assert.equal(reg.count(), 1)
  assert.equal(reg.get('dev_0000000000000001')?.pub, 'pk1')
  assert.equal(reg.list().length, 1)
})

test('registry：重复配对更新属性、created_at 不变、公钥可轮换', () => {
  const reg = mk()
  reg.upsert({ devId: 'dev_0000000000000002', pub: 'old', roles: ['app'], now: 1000 })
  const d = reg.upsert({ devId: 'dev_0000000000000002', pub: 'new', roles: ['app', 'ext'], now: 2000 })
  assert.equal(d.created_at, 1000, '创建时间不变')
  assert.equal(d.pub, 'new', '公钥轮换生效')
  assert.deepEqual(d.roles, ['app', 'ext'])
  assert.equal(d.last_seen, 2000)
})

test('registry：单主控（新主控顶替旧主控）', () => {
  const reg = mk()
  reg.upsert({ devId: 'dev_0000000000000001', pub: 'p1', now: 1000 })
  reg.upsert({ devId: 'dev_0000000000000002', pub: 'p2', now: 1000 })
  assert.ok(reg.claimController('dev_0000000000000001'))
  assert.ok(reg.isController('dev_0000000000000001'))
  assert.ok(reg.claimController('dev_0000000000000002'))
  assert.ok(!reg.isController('dev_0000000000000001'), '旧主控应被顶替')
  assert.equal(reg.controller()?.dev_id, 'dev_0000000000000002')
  reg.setRevoked('dev_0000000000000002', 9999)
  assert.ok(!reg.claimController('dev_0000000000000002'), '已撤销设备不能当主控')
})

test('registry：touch / setScopes / setRevoked', () => {
  const reg = mk()
  reg.upsert({ devId: 'dev_0000000000000001', pub: 'p1', now: 1000 })
  reg.touch('dev_0000000000000001', 5000)
  assert.equal(reg.get('dev_0000000000000001')?.last_seen, 5000)
  reg.setScopes('dev_0000000000000001', 'manage')
  assert.equal(reg.get('dev_0000000000000001')?.scopes, 'manage')
  reg.setRevoked('dev_0000000000000001', 6000)
  assert.equal(reg.get('dev_0000000000000001')?.revoked_at, 6000)
})
