/**
 * 会话管理器：daemon 的在线设备会话表 + 命令下发 + 结果回注。
 *
 * 从 daemon.ts 拆出（单一职责）：Daemon 持有状态，SessionManager 管生命周期与推送。
 */
import type { WireSession } from './session'
import type { OutboundQueue, QueueItem } from './queue'
import type { Registry } from './registry'

export interface PushResult {
  pushed: QueueItem[]
}

export class SessionManager {
  /** dev_id → 在线会话（同一设备重复 hello 时顶替旧会话） */
  #sessions = new Map<string, WireSession>()

  constructor(
    private readonly queue: OutboundQueue,
    private readonly registry: Registry,
    private readonly log: (line: string) => void,
  ) {}

  /** 注册上线会话；顶替同设备旧会话（旧 close 事件由 WS 层自然触发，此处先摘除映射防误推） */
  online(devId: string, session: WireSession): void {
    const old = this.#sessions.get(devId)
    if (old && old !== session) {
      this.#sessions.delete(devId)
      try {
        old.close(4000)
      } catch {
        /* ignore */
      }
    }
    this.#sessions.set(devId, session)
  }

  offline(session: WireSession): void {
    for (const [devId, s] of this.#sessions) {
      if (s === session) this.#sessions.delete(devId)
    }
  }

  isOnline(devId: string): boolean {
    const s = this.#sessions.get(devId)
    return s !== undefined && !s.closed
  }

  onlineCount(): number {
    return this.#sessions.size
  }

  /** 把该设备队列里的命令推给在线会话；返回实际推送的条目 */
  flush(devId: string): PushResult {
    const session = this.#sessions.get(devId)
    const pushed: QueueItem[] = []
    if (!session || session.closed) return { pushed }
    for (let item = this.queue.next(devId); item; item = this.queue.next(devId)) {
      const sent = this.queue.markSent(item.id)
      if (!sent) break
      session.send({
        t: 'cmd',
        id: sent.id,
        ch: sent.ch,
        op: sent.op,
        args: sent.args,
        ttl_ms: sent.ttl_ms,
        idem: sent.idem,
        ...(sent.preconditions ? { if: sent.preconditions } : {}),
      })
      pushed.push(sent)
    }
    if (pushed.length > 0) this.log(`命令下发 ×${pushed.length} → ${devId}`)
    return { pushed }
  }

  /** 入队并即时推送（设备离线则留队列） */
  submit(input: Parameters<OutboundQueue['enqueue']>[0]): { ok: boolean; duplicate?: boolean; id: string } {
    const enq = this.queue.enqueue(input)
    const dev = this.registry.get(input.devId)
    if (enq.ok && dev && dev.revoked_at === null) this.flush(input.devId)
    return { ok: enq.ok, duplicate: enq.duplicate, id: enq.item.id }
  }

  /** 设备回包结算（含 ack 帧处理） */
  settle(ref: string, msg: Record<string, unknown>): boolean {
    const item = this.queue.get(ref)
    if (!item) return false
    if (msg.t === 'ack') {
      this.log(`ack：${item.op}`)
      return true
    }
    this.queue.settle(ref, {
      ok: msg.ok === true,
      status: (msg.status as 'applied' | 'deferred' | 'rejected') ?? 'rejected',
      data: (msg.data as Record<string, unknown>) ?? undefined,
      err: (msg.err as Record<string, unknown>) ?? undefined,
    })
    this.log(`命令结算：${item.op} → ${msg.status}`)
    return true
  }
}
