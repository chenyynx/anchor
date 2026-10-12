/** 配对口令 URI 解析（与 pairing.ts 的 buildPairingURI 互为逆操作）。 */
export interface ParsedPairingURI {
  v: number
  /** base64url 的 agent X25519 公钥（43 字符） */
  k: string
  /** 一次性口令（22 字符） */
  s: string
  endpoints: string[]
  name?: string
  /** 到期 unix 秒 */
  x?: number
}

export const parsePairingURI = (uri: string): ParsedPairingURI => {
  let u: URL
  try {
    u = new URL(uri)
  } catch {
    throw new Error('配对 URI 不是合法 URL')
  }
  if (u.protocol !== 'hako:' || u.host !== 'pair') {
    throw new Error('不是 hako://pair 配对 URI')
  }
  const q = u.searchParams
  const v = Number(q.get('v'))
  const k = q.get('k')
  const s = q.get('s')
  const e = q.get('e')
  if (v !== 1 || !k || !s || !e) {
    throw new Error('配对 URI 缺少必要字段（v/k/s/e）')
  }
  const out: ParsedPairingURI = {
    v,
    k,
    s,
    endpoints: e.split(',').map((x) => decodeURIComponent(x)),
  }
  const n = q.get('n')
  if (n) out.name = decodeURIComponent(n)
  const x = q.get('x')
  if (x) out.x = Number(x)
  return out
}
