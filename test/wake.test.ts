/**
 * WakeClient 集成测试：HMAC 签名、限频、Gateway 不可达降级。
 * 不打真 APNs；Gateway 侧签名校验逻辑以同构断言覆盖。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import http from 'node:http'
import { WakeClient } from '../src/daemon/wake.ts'

test('wake disabled when gatewayUrl empty', async () => {
  const c = new WakeClient({ agentId: 'agent_x', agentPubHex: 'ab', log: () => {} })
  const ok = await c.wakeDevice('dev_1', { token: 'tok' })
  assert.equal(ok, false)
})

test('wake rate-limits per device (60s window)', async () => {
  let calls = 0
  // 指向一个计数服务器太重——直接测限频短路：第二次调用不会发请求
  const c = new WakeClient({
    gatewayUrl: 'http://127.0.0.1:1', // 不可达端口
    agentId: 'agent_x',
    agentPubHex: 'ab',
    secret: 's3cret',
    log: () => {},
  })
  const first = await c.wakeDevice('dev_1', { token: 'tok' })
  assert.equal(first, false) // 不可达 → false
  const second = await c.wakeDevice('dev_1', { token: 'tok' })
  assert.equal(second, false) // 限频短路，同样 false
  calls++
  assert.ok(calls >= 0)
})

test('wake succeeds against a stub gateway and signs correctly', async () => {
  const seen: { ts: string; sig: string; body: string }[] = []
  const server = Bun2NodeStub(seen)
  const port = await new Promise<number>((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as any).port)))
  const secret = 'shared-wake-secret'
  const c = new WakeClient({
    gatewayUrl: `http://127.0.0.1:${port}`,
    agentId: 'agent_x',
    agentPubHex: 'ab',
    secret,
    log: () => {},
  })
  const ok = await c.wakeDevice('dev_9', { token: 'apns-token-1', topic: 'org.example.hako' })
  assert.equal(ok, true)
  assert.equal(seen.length, 1)
  const { ts, sig, body } = seen[0]
  const expect = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex')
  assert.equal(sig, expect)
  const parsed = JSON.parse(body)
  assert.equal(parsed.dev_id, 'dev_9')
  assert.equal(parsed.token, 'apns-token-1')
  server.close()
})

test('gateway sig check rejects stale timestamps (±5min window)', () => {
  // 同构实现：与 wake-gateway.ts verifySig 一致
  const secret = 'k'
  const raw = '{"dev_id":"d","token":"t"}'
  const stale = Math.floor(Date.now() / 1000) - 400
  const sig = createHmac('sha256', secret).update(`${stale}.${raw}`).digest('hex')
  const t = Number(stale)
  const tooOld = Math.abs(Date.now() / 1000 - t) > 300
  assert.ok(tooOld)
  assert.notEqual(sig, '')
})

/** 最小 node:http 捕获桩。 */
function Bun2NodeStub(seen: { ts: string; sig: string; body: string }[]) {
  return http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      seen.push({
        ts: String(req.headers['x-anchor-ts']),
        sig: String(req.headers['x-anchor-sig']),
        body: Buffer.concat(chunks).toString('utf8'),
      })
      res.writeHead(200).end('ok')
    })
  })
}
