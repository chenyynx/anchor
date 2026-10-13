/**
 * WakeClient — 设备离线时唤醒它（P4 后台可达）。
 *
 * 链路：submitCommand 发现设备不在线且已登记 APNs token →
 *   POST {gateway}/v1/wake { dev_id, agent_id, apns_topic } →
 *   Gateway 用发布方 APNs 密钥发静默推送（content-available）→
 *   iOS 拉起 Hako App 数十秒 → App 连接 daemon 收队列命令。
 *
 * 安全模型：
 *  - Gateway 无状态、不存业务数据；payload 不含命令内容（只有设备/agent 标识）
 *  - 防滥用：Gateway 校验 agent_id ↔ dev_id 的配对绑定（注册时提交），签名见下
 *  - 唤醒限频：同设备 60s 窗口内最多 1 次（Apple 也压制频繁静默推送）
 */
import { createHmac } from 'node:crypto'

export interface WakeClientOptions {
  /** Gateway base URL，如 https://wake.example.com；空 = 不启用唤醒 */
  gatewayUrl?: string
  /** daemon 的 agent_id（配对身份） */
  agentId: string
  /** daemon 静态公钥（hex）——Gateway 用它校验请求 HMAC */
  agentPubHex: string
  /** daemon 与 Gateway 的共享密钥（注册 Gateway 时双方交换；不落库时用环境变量） */
  secret?: string
  log?: (line: string) => void
}

export class WakeClient {
  #secret?: string
  #lastWakeAt = new Map<string, number>()
  /** 同设备最小唤醒间隔（ms）。Apple 对频繁静默推送限频，宁可保守。 */
  static minIntervalMs = 60_000

  constructor(private readonly o: WakeClientOptions) {
    this.#secret = o.secret ?? process.env.ANCHOR_WAKE_SECRET
  }

  /** 设备不在线时调用。返回 true = 已发起唤醒请求。 */
  async wakeDevice(devId: string, apns: { token: string; topic?: string }): Promise<boolean> {
    if (!this.o.gatewayUrl) return false
    const now = Date.now()
    const last = this.#lastWakeAt.get(devId) ?? 0
    if (now - last < WakeClient.minIntervalMs) return false
    this.#lastWakeAt.set(devId, now)

    const body = JSON.stringify({
      dev_id: devId,
      agent_id: this.o.agentId,
      token: apns.token,
      apns_topic: apns.topic ?? null,
    })
    const ts = Math.floor(now / 1000)
    const mac = createHmac('sha256', this.#secret ?? '')
      .update(`${ts}.${body}`)
      .digest('hex')

    try {
      const res = await fetch(`${this.o.gatewayUrl.replace(/\/$/, '')}/v1/wake`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-anchor-ts': String(ts),
          'x-anchor-sig': mac,
        },
        body,
        signal: AbortSignal.timeout(5000),
      })
      if (!res.ok) {
        this.o.log?.(`wake: gateway ${res.status} for ${devId}`)
        return false
      }
      this.o.log?.(`wake: pushed via gateway for ${devId}`)
      return true
    } catch (e) {
      this.o.log?.(`wake: gateway unreachable (${String(e).slice(0, 80)})`)
      return false
    }
  }
}
