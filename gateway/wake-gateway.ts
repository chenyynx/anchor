/**
 * Wake Gateway 参考实现 — 「唤醒某设备」→ APNs 静默推送（P4）。
 *
 * 设计（v4 方案）：
 *  - 无状态：不存设备数据、不存业务 payload。请求即转发，转完即忘。
 *  - APNs 密钥属于 App 发布方（.p8 + key id + team id + topic），环境变量注入。
 *  - 安全：请求方（daemon）带 HMAC-SHA256(ts.body) 签名（ANCHOR_WAKE_SECRET）。
 *    Gateway 不存配对表——伪造唤醒最多浪费一次静默推送，无安全后果
 *    （真正的命令面由 Noise 会话层把守，只有配对 agent 能下发）。
 *  - 限频：同 apns token 60s 一次（Apple 对频繁静默推送自己也压制）。
 *
 * 请求协议：POST /v1/wake
 *   headers: x-anchor-ts <unix 秒>   x-anchor-sig <hex HMAC(ts+"."+body)>
 *   body:    {"dev_id": "...", "token": "<apns hex token>", "topic": "bundle.id"（可选，自编译客户端 bundle id 不同时用）}
 *
 * 环境变量：
 *   ANCHOR_WAKE_SECRET  与 daemon 共享的 HMAC 密钥（必填）
 *   APNS_KEY_P8         .p8 私钥 PEM（必填，含 \n 转义或真实换行）
 *   APNS_KEY_ID         密钥 id（必填）
 *   APNS_TEAM_ID        团队 id（必填）
 *   ANCHOR_APNS_TOPIC   默认 topic（默认 org.example.hako）
 *   APNS_ENV            prod（默认）| sandbox
 *   PORT                默认 8787
 *
 * 零依赖。运行：npx tsx gateway/wake-gateway.ts
 */
import http from 'node:http'
import crypto from 'node:crypto'

const SECRET = process.env.ANCHOR_WAKE_SECRET
const P8 = process.env.APNS_KEY_P8
const KEY_ID = process.env.APNS_KEY_ID
const TEAM_ID = process.env.APNS_TEAM_ID
const DEFAULT_TOPIC = process.env.ANCHOR_APNS_TOPIC ?? 'org.example.hako'
const PORT = Number(process.env.PORT ?? 8787)
const APNS_HOST = process.env.APNS_ENV === 'sandbox' ? 'api.sandbox.push.apple.com' : 'api.push.apple.com'

if (!SECRET || !P8 || !KEY_ID || !TEAM_ID) {
  console.error('[wake-gateway] missing env: ANCHOR_WAKE_SECRET / APNS_KEY_P8 / APNS_KEY_ID / APNS_TEAM_ID')
  process.exit(1)
}

// ---------- APNs provider token（ES256 JWT） ----------

let cachedToken: { jwt: string; exp: number } | null = null

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function providerToken(): string {
  const now = Math.floor(Date.now() / 1000)
  if (cachedToken && cachedToken.exp - 60 > now) return cachedToken.jwt
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid: KEY_ID })))
  const claims = b64url(Buffer.from(JSON.stringify({ iss: TEAM_ID, iat: now })))
  const unsigned = `${header}.${claims}`
  const keyPem = P8!.includes('\\n') ? P8!.replace(/\\n/g, '\n') : P8!
  const sig = crypto.sign('sha256', Buffer.from(unsigned), {
    key: keyPem,
    dsaEncoding: 'ieee-p1363', // APNs 要 r||s，不是 DER
  })
  cachedToken = { jwt: `${unsigned}.${b64url(sig)}`, exp: now + 1800 }
  return cachedToken.jwt
}

// ---------- 限频（内存 LRU，进程重启即清零——无状态原则） ----------

const lastWake = new Map<string, number>()
const MIN_INTERVAL_MS = 60_000

function rateLimited(key: string, now: number): boolean {
  const last = lastWake.get(key) ?? 0
  if (now - last < MIN_INTERVAL_MS) return true
  lastWake.set(key, now)
  if (lastWake.size > 10_000) {
    const cutoff = now - MIN_INTERVAL_MS
    for (const [k, t] of lastWake) if (t < cutoff) lastWake.delete(k)
  }
  return false
}

// ---------- APNs 静默推送 ----------

async function pushSilent(token: string, topic: string, devId: string): Promise<{ status: number; body: string }> {
  const payload = JSON.stringify({
    aps: { 'content-available': 1 },
    anchor: { dev: devId, reason: 'wake' }, // 只带标识，不带业务数据
  })
  const res = await fetch(`https://${APNS_HOST}/3/device/${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: {
      authorization: `bearer ${providerToken()}`,
      'apns-topic': topic,
      'apns-push-type': 'background', // 静默推送必须 background
      'apns-priority': '5', // 静默推送必须 5，10 会被 APNs 拒
      'apns-expiration': '0', // 不在线就丢弃，醒来后设备主动连 daemon
    },
    body: payload,
  })
  const body = res.status === 200 ? 'ok' : await res.text().catch(() => '')
  return { status: res.status, body }
}

// ---------- 签名校验 ----------

function verifySig(raw: string, ts: string, sig: string): boolean {
  const t = Number(ts)
  if (!Number.isFinite(t) || Math.abs(Date.now() / 1000 - t) > 300) return false // ±5min 防重放
  const expect = crypto.createHmac('sha256', SECRET!).update(`${ts}.${raw}`).digest('hex')
  const a = Buffer.from(expect)
  const b = Buffer.from(sig)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

// ---------- HTTP ----------

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200).end('ok')
    return
  }
  if (req.method !== 'POST' || req.url !== '/v1/wake') {
    res.writeHead(404).end()
    return
  }
  const chunks: Buffer[] = []
  for await (const c of req) chunks.push(c as Buffer)
  const raw = Buffer.concat(chunks).toString('utf8')
  const ts = String(req.headers['x-anchor-ts'] ?? '')
  const sig = String(req.headers['x-anchor-sig'] ?? '')
  if (!verifySig(raw, ts, sig)) {
    res.writeHead(401).end(JSON.stringify({ error: 'bad signature' }))
    return
  }
  try {
    const { dev_id: devId, token, topic } = JSON.parse(raw)
    if (typeof devId !== 'string' || typeof token !== 'string' || token.length === 0) {
      res.writeHead(400).end(JSON.stringify({ error: 'dev_id and token required' }))
      return
    }
    if (rateLimited(token, Date.now())) {
      res.writeHead(429).end(JSON.stringify({ error: 'rate limited' }))
      return
    }
    const out = await pushSilent(token, typeof topic === 'string' && topic ? topic : DEFAULT_TOPIC, devId)
    res.writeHead(out.status).end(out.body)
  } catch (e) {
    res.writeHead(500).end(JSON.stringify({ error: String(e).slice(0, 200) }))
  }
})

server.listen(PORT, () => {
  console.log(`[wake-gateway] :${PORT} env=${APNS_HOST} topic=${DEFAULT_TOPIC}`)
})
