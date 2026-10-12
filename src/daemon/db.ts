/**
 * SQLite 打开与建表（node:sqlite，Node 22 内置，零依赖）。
 * 单库承担：设备注册表 devices + 出站命令队列 commands + 杂项 meta。
 */
import { DatabaseSync } from 'node:sqlite'

export type Db = DatabaseSync

const SCHEMA = `
CREATE TABLE IF NOT EXISTS devices (
  dev_id        TEXT PRIMARY KEY,
  pub           TEXT NOT NULL,
  alias         TEXT,
  created_at    INTEGER NOT NULL,
  last_seen     INTEGER,
  roles         TEXT NOT NULL DEFAULT '[]',
  scopes        TEXT NOT NULL DEFAULT 'operate',
  is_controller INTEGER NOT NULL DEFAULT 0,
  apns_token    TEXT,
  apns_env      TEXT,
  apns_topic    TEXT,
  revoked_at    INTEGER
);

CREATE TABLE IF NOT EXISTS commands (
  id            TEXT PRIMARY KEY,
  dev_id        TEXT NOT NULL,
  ch            TEXT NOT NULL,
  op            TEXT NOT NULL,
  args          TEXT NOT NULL DEFAULT '{}',
  idem          TEXT NOT NULL,
  ttl_ms        INTEGER NOT NULL DEFAULT 30000,
  preconditions TEXT,
  state         TEXT NOT NULL DEFAULT 'queued',
  seq           INTEGER,
  attempts      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  sent_at       INTEGER,
  settled_at    INTEGER,
  result        TEXT,
  err           TEXT,
  UNIQUE (dev_id, idem)
);
CREATE INDEX IF NOT EXISTS idx_commands_dev_state ON commands (dev_id, state);

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`

export const openDb = (path: string): Db => {
  const db = new DatabaseSync(path)
  db.exec('PRAGMA foreign_keys = ON')
  if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL')
  db.exec(SCHEMA)
  return db
}

export const metaGet = (db: Db, k: string): string | null => {
  const row = db.prepare('SELECT v FROM meta WHERE k = ?').get(k) as { v: string } | undefined
  return row?.v ?? null
}

export const metaSet = (db: Db, k: string, v: string): void => {
  db.prepare(
    'INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
  ).run(k, v)
}
