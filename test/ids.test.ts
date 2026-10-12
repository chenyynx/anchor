import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { agentIdFromPub, deviceIdFromPub, isDeviceId, isUlid, ulid } from '../src/lib/ids'

test('ulid：26 字符、字符集合法', () => {
  const u = ulid()
  assert.equal(u.length, 26)
  assert.ok(isUlid(u))
})

test('ulid：同毫秒单调递增', () => {
  const t = 1750000000000
  const a = ulid(t)
  const b = ulid(t)
  const c = ulid(t)
  assert.ok(a < b && b < c, `${a} < ${b} < ${c}`)
})

test('ulid：时间有序（前缀随毫秒递增）', () => {
  const a = ulid(1000)
  const b = ulid(2000)
  assert.ok(a.slice(0, 10) < b.slice(0, 10))
})

test('agentId：16 字符、由公钥唯一确定', () => {
  const pub = randomBytes(32)
  const id = agentIdFromPub(pub)
  assert.equal(id.length, 16)
  assert.match(id, /^[0-9A-Z]{16}$/)
  assert.equal(id, agentIdFromPub(pub), '同公钥同 id')
  assert.notEqual(id, agentIdFromPub(randomBytes(32)), '不同公钥不同 id')
})

test('deviceId：dev_ 前缀 + 16 字符', () => {
  const id = deviceIdFromPub(randomBytes(32))
  assert.ok(id.startsWith('dev_'))
  assert.ok(isDeviceId(id))
  assert.ok(!isDeviceId('dev_short'))
})
