import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import { PairingWindows, b64url, buildPairingURI } from '../src/daemon/pairing'

const here = dirname(fileURLToPath(import.meta.url))
const schema = JSON.parse(
  readFileSync(join(here, '../packages/hako-protocol/schema/pairing.schema.json'), 'utf8'),
) as { $defs: Record<string, object> }
const ajv = new Ajv2020({ allErrors: true, strict: false })
const validateURI = ajv.compile({ ...schema.$defs.pairingURI })

const K = b64url(randomBytes(32))

test('pairing：生成的 URI 通过官方 schema 校验', () => {
  const ws = new PairingWindows()
  const w = ws.open(
    {
      k: K,
      endpoints: ['lan:192.168.1.20:8787', 'wss://hako.example.com/ws'],
      name: 'MacBook Pro',
    },
    1750000000000,
  )
  assert.ok(validateURI(w.uri), `应合法：${w.uri}（${ajv.errorsText(validateURI.errors)}）`)
  assert.equal(w.secret.length, 22)
  assert.equal(K.length, 43)
  assert.ok(w.uri.startsWith('hako://pair?v=1&k='))
})

test('pairing：x= 为秒级到期时间（now + ttl）', () => {
  const ws = new PairingWindows({ ttlSec: 120 })
  const w = ws.open({ k: K, endpoints: ['lan:host:8787'] }, 1750000000000)
  const m = /[?&]x=(\d+)/.exec(w.uri)
  assert.ok(m, '应有 x 字段')
  assert.equal(Number(m![1]), Math.floor(1750000000000 / 1000) + 120)
})

test('pairing：一次性消费，二次消费失败', () => {
  const ws = new PairingWindows()
  const w = ws.open({ k: K, endpoints: ['lan:h:1'] }, 1000)
  assert.ok(ws.verify(w.secret, 1000))
  const consumed = ws.consume(w.secret, 1000)
  assert.equal(consumed?.id, w.id)
  assert.equal(ws.consume(w.secret, 1000), undefined, '口令只能消费一次')
})

test('pairing：过期窗口被清扫、过期口令不可用', () => {
  const ws = new PairingWindows({ ttlSec: 120 })
  const w = ws.open({ k: K, endpoints: ['lan:h:1'] }, 0)
  assert.equal(ws.active(119000).length, 1)
  assert.equal(ws.sweep(120001), 1)
  assert.equal(ws.verify(w.secret, 120001), undefined)
})

test('pairing：窗口数量上限', () => {
  const ws = new PairingWindows({ max: 2 })
  ws.open({ k: K, endpoints: ['a'] }, 0)
  ws.open({ k: K, endpoints: ['a'] }, 0)
  assert.throws(() => ws.open({ k: K, endpoints: ['a'] }, 0), /过多/)
})

test('pairing：端点转义 / n 可选', () => {
  const uri = buildPairingURI({
    k: K,
    secret: 'A'.repeat(22),
    endpoints: ['wss://x.dev/ws?a=1'],
    expiresAt: 0,
  })
  assert.ok(uri.includes('e=wss%3A%2F%2Fx.dev%2Fws%3Fa%3D1'))
  assert.ok(!uri.includes('&n='))
})
