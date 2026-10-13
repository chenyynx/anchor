/** 出站命令队列：agent → 设备。断线排队、重连补发、幂等去重、TTL 过期。 */
import { ulid } from '../lib/ids'
import type { Db } from './db'

export type QueueState = 'queued' | 'sent' | 'applied' | 'deferred' | 'rejected' | 'expired'

export interface Preconditions {
  rev?: number
  epoch?: number
}

export interface EnqueueInput {
  devId: string
  ch: 'app' | 'ext'
  op: string
  args?: Record<string, unknown>
  /** 幂等键，缺省等于命令 id（与 envelope.idem 语义一致） */
  idem?: string
  ttl_ms?: number
  preconditions?: Preconditions
}

export interface QueueItem {
  id: string
  dev_id: string
  ch: string
  op: string
  args: Record<string, unknown>
  idem: string
  ttl_ms: number
  preconditions: Preconditions | null
  state: QueueState
  seq: number | null
  attempts: number
  created_at: number
  sent_at: number | null
  settled_at: number | null
  result: Record<string, unknown> | null
  err: Record<string, unknown> | null
}

interface Row {
  id: string
  dev_id: string
  ch: string
  op: string
  args: string
  idem: string
  ttl_ms: number
  preconditions: string | null
  state: string
  seq: number | null
  attempts: number
  created_at: number
  sent_at: number | null
  settled_at: number | null
  result: string | null
  err: string | null
}

const toItem = (r: Row): QueueItem => ({
  id: r.id,
  dev_id: r.dev_id,
  ch: r.ch,
  op: r.op,
  args: JSON.parse(r.args) as Record<string, unknown>,
  idem: r.idem,
  ttl_ms: r.ttl_ms,
  preconditions: r.preconditions
    ? (JSON.parse(r.preconditions) as Preconditions)
    : null,
  state: r.state as QueueState,
  seq: r.seq,
  attempts: r.attempts,
  created_at: r.created_at,
  sent_at: r.sent_at,
  settled_at: r.settled_at,
  result: r.result ? (JSON.parse(r.result) as Record<string, unknown>) : null,
  err: r.err ? (JSON.parse(r.err) as Record<string, unknown>) : null,
})

export class OutboundQueue {
  constructor(private readonly db: Db) {}

  /** 入队；同设备同幂等键视为重复，返回既有条目 */
  enqueue(
    input: EnqueueInput,
    now = Date.now(),
  ): { ok: boolean; duplicate?: boolean; item: QueueItem } {
    const id = ulid(now)
    const idem = input.idem ?? id
    const existing = this.#byIdem(input.devId, idem)
    if (existing) return { ok: false, duplicate: true, item: existing }

    this.db
      .prepare(
        `INSERT INTO commands (id, dev_id, ch, op, args, idem, ttl_ms, preconditions, state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)`,
      )
      .run(
        id,
        input.devId,
        input.ch,
        input.op,
        JSON.stringify(input.args ?? {}),
        idem,
        input.ttl_ms ?? 30000,
        input.preconditions ? JSON.stringify(input.preconditions) : null,
        now,
      )
    return { ok: true, item: this.get(id)! }
  }

  get(id: string): QueueItem | null {
    const row = this.db.prepare('SELECT * FROM commands WHERE id = ?').get(id) as
      | Row
      | undefined
    return row ? toItem(row) : null
  }

  /** 该设备最早的待发送命令 */
  next(devId: string): QueueItem | null {
    const row = this.db
      .prepare(
        `SELECT * FROM commands WHERE dev_id = ? AND state = 'queued' ORDER BY created_at, id LIMIT 1`,
      )
      .get(devId) as Row | undefined
    return row ? toItem(row) : null
  }

  /** 标记已发送：分配通道序号（每设备单调），重发不换号 */
  markSent(id: string, now = Date.now()): QueueItem | null {
    const item = this.get(id)
    if (!item || (item.state !== 'queued' && item.state !== 'sent')) return null
    const nextSeq = (
      this.db
        .prepare('SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM commands WHERE dev_id = ?')
        .get(item.dev_id) as { s: number }
    ).s
    this.db
      .prepare(
        `UPDATE commands SET state = 'sent', seq = COALESCE(seq, ?), attempts = attempts + 1, sent_at = ?
         WHERE id = ?`,
      )
      .run(nextSeq, now, id)
    return this.get(id)
  }

  /** 结算：applied / deferred / rejected */
  settle(
    id: string,
    res: {
      ok: boolean
      status: 'applied' | 'deferred' | 'rejected'
      data?: Record<string, unknown>
      err?: Record<string, unknown>
    },
    now = Date.now(),
  ): QueueItem | null {
    const item = this.get(id)
    if (!item || (item.state !== 'queued' && item.state !== 'sent')) return null
    this.db
      .prepare('UPDATE commands SET state = ?, settled_at = ?, result = ?, err = ? WHERE id = ?')
      .run(
        res.status,
        now,
        res.data ? JSON.stringify(res.data) : null,
        res.err ? JSON.stringify(res.err) : null,
        id,
      )
    return this.get(id)
  }

  /**
   * P4：deferred 重排——命令回到 queued（原 id/idem 不变）。attempts 不再
   * 额外 +1：markSent 投递时已计数，上限判定用它即可。
   */
  requeue(id: string, now = Date.now()): QueueItem | null {
    const item = this.get(id)
    if (!item || item.state !== 'sent') return null
    this.db
      .prepare(
        `UPDATE commands SET state = 'queued', sent_at = NULL, settled_at = NULL,
         result = NULL, err = NULL, created_at = ? WHERE id = ?`,
      )
      .run(now, id)
    return this.get(id)
  }

  /** 清扫过期（queued/sent 且超出 TTL），返回条数 */
  expire(now = Date.now()): number {
    const r = this.db
      .prepare(
        `UPDATE commands SET state = 'expired', settled_at = ?
         WHERE state IN ('queued', 'sent') AND (created_at + ttl_ms) < ?`,
      )
      .run(now, now)
    return Number(r.changes)
  }

  /** 未结算数量（helloRes.pending 用） */
  pendingCount(devId: string): number {
    return (
      this.db
        .prepare(
          `SELECT COUNT(*) AS c FROM commands WHERE dev_id = ? AND state IN ('queued', 'sent')`,
        )
        .get(devId) as { c: number }
    ).c
  }

  list(devId: string, limit = 20): QueueItem[] {
    const rows = this.db
      .prepare(
        'SELECT * FROM commands WHERE dev_id = ? ORDER BY created_at DESC, id DESC LIMIT ?',
      )
      .all(devId, limit) as unknown as Row[]
    return rows.map(toItem)
  }

  #byIdem(devId: string, idem: string): QueueItem | null {
    const row = this.db
      .prepare('SELECT * FROM commands WHERE dev_id = ? AND idem = ?')
      .get(devId, idem) as Row | undefined
    return row ? toItem(row) : null
  }
}
