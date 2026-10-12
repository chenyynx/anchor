/** 设备注册表：配对成功的设备与其属性（单主控约束）。 */
import type { Db } from './db'

export type Scopes = 'observe' | 'operate' | 'manage'

export interface DeviceRecord {
  dev_id: string
  pub: string
  alias: string | null
  created_at: number
  last_seen: number | null
  roles: string[]
  scopes: Scopes
  is_controller: boolean
  apns_token: string | null
  apns_env: string | null
  apns_topic: string | null
  revoked_at: number | null
}

export interface UpsertInput {
  devId: string
  pub: string
  alias?: string | null
  roles?: string[]
  scopes?: Scopes
  apns?: { token: string; env: 'prod' | 'sandbox'; topic?: string }
  now?: number
}

interface Row {
  dev_id: string
  pub: string
  alias: string | null
  created_at: number
  last_seen: number | null
  roles: string
  scopes: string
  is_controller: number
  apns_token: string | null
  apns_env: string | null
  apns_topic: string | null
  revoked_at: number | null
}

const toRecord = (r: Row): DeviceRecord => ({
  dev_id: r.dev_id,
  pub: r.pub,
  alias: r.alias,
  created_at: r.created_at,
  last_seen: r.last_seen,
  roles: JSON.parse(r.roles) as string[],
  scopes: r.scopes as Scopes,
  is_controller: r.is_controller === 1,
  apns_token: r.apns_token,
  apns_env: r.apns_env,
  apns_topic: r.apns_topic,
  revoked_at: r.revoked_at,
})

export class Registry {
  constructor(private readonly db: Db) {}

  upsert(input: UpsertInput): DeviceRecord {
    const now = input.now ?? Date.now()
    this.db
      .prepare(
        `INSERT INTO devices (dev_id, pub, alias, created_at, last_seen, roles, scopes, apns_token, apns_env, apns_topic)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(dev_id) DO UPDATE SET
           pub = excluded.pub,
           alias = COALESCE(excluded.alias, devices.alias),
           last_seen = excluded.last_seen,
           roles = excluded.roles,
           scopes = excluded.scopes,
           apns_token = COALESCE(excluded.apns_token, devices.apns_token),
           apns_env = COALESCE(excluded.apns_env, devices.apns_env),
           apns_topic = COALESCE(excluded.apns_topic, devices.apns_topic)`,
      )
      .run(
        input.devId,
        input.pub,
        input.alias ?? null,
        now,
        now,
        JSON.stringify(input.roles ?? []),
        input.scopes ?? 'operate',
        input.apns?.token ?? null,
        input.apns?.env ?? null,
        input.apns?.topic ?? null,
      )
    return this.get(input.devId)!
  }

  get(devId: string): DeviceRecord | null {
    const row = this.db
      .prepare('SELECT * FROM devices WHERE dev_id = ?')
      .get(devId) as Row | undefined
    return row ? toRecord(row) : null
  }

  list(): DeviceRecord[] {
    const rows = this.db
      .prepare('SELECT * FROM devices ORDER BY created_at, dev_id')
      .all() as unknown as Row[]
    return rows.map(toRecord)
  }

  count(): number {
    return (this.db.prepare('SELECT COUNT(*) AS c FROM devices').get() as { c: number }).c
  }

  touch(devId: string, now = Date.now()): void {
    this.db.prepare('UPDATE devices SET last_seen = ? WHERE dev_id = ?').run(now, devId)
  }

  setScopes(devId: string, scopes: Scopes): void {
    this.db.prepare('UPDATE devices SET scopes = ? WHERE dev_id = ?').run(scopes, devId)
  }

  setRevoked(devId: string, at: number | null): void {
    this.db.prepare('UPDATE devices SET revoked_at = ? WHERE dev_id = ?').run(at, devId)
  }

  /** 单主控：置为唯一主控（已撤销设备不能当主控） */
  claimController(devId: string): boolean {
    const d = this.get(devId)
    if (!d || d.revoked_at !== null) return false
    this.db.exec('BEGIN')
    try {
      this.db.prepare('UPDATE devices SET is_controller = 0 WHERE is_controller = 1').run()
      this.db.prepare('UPDATE devices SET is_controller = 1 WHERE dev_id = ?').run(devId)
      this.db.exec('COMMIT')
    } catch (e) {
      this.db.exec('ROLLBACK')
      throw e
    }
    return true
  }

  controller(): DeviceRecord | null {
    const row = this.db
      .prepare('SELECT * FROM devices WHERE is_controller = 1 LIMIT 1')
      .get() as Row | undefined
    return row ? toRecord(row) : null
  }

  isController(devId: string): boolean {
    const r = this.db
      .prepare('SELECT is_controller FROM devices WHERE dev_id = ?')
      .get(devId) as { is_controller: number } | undefined
    return r?.is_controller === 1
  }
}
