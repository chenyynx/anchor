import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createIdentity,
  loadIdentity,
  loadOrCreateIdentity,
  parseIdentityFile,
  saveIdentity,
} from '../src/daemon/identity'

const tmpHome = () => mkdtempSync(join(tmpdir(), 'hako-identity-'))

test('identity：创建并落盘（0600），重载稳定', () => {
  const home = tmpHome()
  try {
    const { ident, created } = loadOrCreateIdentity(home, 1750000000000)
    assert.ok(created)
    assert.match(ident.agentId, /^[0-9A-Z]{16}$/)
    const mode = statSync(join(home, 'identity.json')).mode & 0o777
    assert.equal(mode, 0o600)
    const again = loadIdentity(home)
    assert.equal(again.agentId, ident.agentId)
    assert.deepEqual(again.edPubRaw, ident.edPubRaw)
    assert.deepEqual(again.xPubRaw, ident.xPubRaw)
    const { created: created2 } = loadOrCreateIdentity(home)
    assert.equal(created2, false, '第二次加载不应新建')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('identity：签名/验签 与 篡改检测', () => {
  const home = tmpHome()
  try {
    const { ident } = loadOrCreateIdentity(home)
    const sig = ident.sign(Buffer.from('ping'))
    assert.ok(ident.verify(Buffer.from('ping'), sig))
    assert.ok(!ident.verify(Buffer.from('pong'), sig))

    const p = join(home, 'identity.json')
    const f = JSON.parse(readFileSync(p, 'utf8')) as { agent_id: string }
    f.agent_id = 'AAAAAAAAAAAAAAAA'
    writeFileSync(p, JSON.stringify(f))
    assert.throws(
      () => loadIdentity(home),
      (e: unknown) => String((e as Error).message).includes('不匹配'),
    )
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('identity：导出/导入保真（换机迁移）', () => {
  const homeA = tmpHome()
  const homeB = tmpHome()
  try {
    const { ident } = loadOrCreateIdentity(homeA)
    const parsed = parseIdentityFile(JSON.stringify(ident.toFile()))
    assert.equal(parsed.agentId, ident.agentId)
    saveIdentity(homeB, parsed)
    const migrated = loadIdentity(homeB)
    assert.equal(migrated.agentId, ident.agentId)
    const sig = migrated.sign(Buffer.from('x'))
    assert.ok(ident.verify(Buffer.from('x'), sig), '迁移后签名应能被原身份验证')
  } finally {
    rmSync(homeA, { recursive: true, force: true })
    rmSync(homeB, { recursive: true, force: true })
  }
})

test('identity：独立生成不重复', () => {
  assert.notEqual(createIdentity().agentId, createIdentity().agentId)
})
