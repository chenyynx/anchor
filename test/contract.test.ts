/**
 * Hako agent wire protocol v1 — 契约测试
 *
 * 用共享测试向量（test/vectors.json）校验三份 JSON Schema。
 * 同一套向量会在 Swift 侧（HakoAgentKit）再跑一遍，两边结果必须一致——
 * 这是「双方手写 Noise / 协议」的对齐机制。
 *
 * 运行：npm run contract
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const schemaDir = join(root, 'packages/hako-protocol/schema')

const loadSchema = (name: string) =>
  JSON.parse(readFileSync(join(schemaDir, name), 'utf8'))

const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)

const envelopeSchema = loadSchema('envelope.schema.json')
const pairingSchema = loadSchema('pairing.schema.json')
const opsSchema = loadSchema('ops.schema.json')

// 逐条校验需要单独构造 validator：envelope 的 allOf/if-then 在 $ref 下用同一实例缓存会串味
const validateEnvelope = ajv.compile(envelopeSchema)
const validatePairingURI = ajv.compile({ ...pairingSchema.$defs.pairingURI })
const validatePairReq = ajv.compile({ ...pairingSchema.$defs.pairReq })
const validatePairRes = ajv.compile({ ...pairingSchema.$defs.pairRes })
const validateHello = ajv.compile({ ...pairingSchema.$defs.hello })
const validateHelloRes = ajv.compile({ ...pairingSchema.$defs.helloRes })

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'))

/** op 命名空间 → 目标通道 */
export const routeOf = (op: string): 'app' | 'ext' | 'device' | 'evt' | null => {
  const ns = op.split('.')[0]
  switch (ns) {
    case 'app': return 'app'
    case 'core': return 'ext'
    case 'device': return 'device'
    case 'evt': return 'evt'
    default: return null
  }
}

/** 向量里的 note/why/expectCh 是测试注解，不属于协议载荷，校验前剥离 */
const payload = <T extends Record<string, unknown>>(v: T): T => {
  const { note, why, expectCh, ...rest } = v as Record<string, unknown>
  return rest as T
}

test('envelope：合法向量全部通过', () => {
  for (const v of vectors.vectors.envelopeValid) {
    const ok = validateEnvelope(v.data)
    assert.ok(ok, `${v.name} 应合法，实际错误：${ajv.errorsText(validateEnvelope.errors)}`)
  }
})

test('envelope：非法向量全部被拒', () => {
  for (const v of vectors.vectors.envelopeInvalid) {
    const ok = validateEnvelope(v.data)
    assert.ok(!ok, `${v.name} 应被拒绝，但通过了`)
  }
})

test('envelope：未知字段向后兼容（附加字段被忽略而非拒绝）', () => {
  const frame = {
    ...vectors.vectors.envelopeValid[0].data,
    futureField: { anything: true },
  }
  assert.ok(validateEnvelope(frame), '新增字段不应破坏旧接收方')
})

test('envelope：ttl_ms 边界', () => {
  const base = vectors.vectors.envelopeValid[0].data
  assert.ok(validateEnvelope({ ...base, ttl_ms: 1000 }), '下界 1000 应合法')
  assert.ok(validateEnvelope({ ...base, ttl_ms: 600000 }), '上界 600000 应合法')
  assert.ok(!validateEnvelope({ ...base, ttl_ms: 999 }), '低于下界应拒绝')
  assert.ok(!validateEnvelope({ ...base, ttl_ms: 600001 }), '高于上界应拒绝')
})

test('pairing：口令 URI 校验', () => {
  for (const uri of vectors.vectors.pairing.uriValid) {
    assert.ok(validatePairingURI(uri), `应合法：${uri}`)
  }
  for (const uri of vectors.vectors.pairing.uriInvalid) {
    assert.ok(!validatePairingURI(uri), `应拒绝：${uri}`)
  }
})

test('pairing：payload 校验', () => {
  const P = vectors.vectors.pairing
  assert.ok(validatePairReq(payload(P.pairReqValid)), 'QR 路径 pair.req')
  assert.ok(validatePairReq(payload(P.pairReqBonjour)), 'Bonjour 路径 pair.req（无 secret）')
  assert.ok(validatePairRes(payload(P.pairResAccepted)), 'accepted')
  assert.ok(validatePairRes(payload(P.pairResNeedConfirm)), 'need_confirm')
  assert.ok(validateHello(payload(P.helloApp)), 'hello(app)')
  assert.ok(validateHello(payload(P.helloExt)), 'hello(ext) 带 session_epoch')
  assert.ok(validateHelloRes(payload(P.helloResOk)), 'hello.ok 完整能力')
  assert.ok(validateHelloRes(payload(P.helloResDegradedA)), 'hello.ok 降级 A 级')
  assert.ok(validateHelloRes(payload(P.helloResRevoked)), 'hello 失败')
})

test('pairing：hello 的 ext 必须带 session_epoch（app 则不应带）', () => {
  const hello = vectors.vectors.pairing.helloExt
  const stripped = { ...hello }
  delete (stripped as Record<string, unknown>).session_epoch
  assert.ok(
    !validateHello(stripped),
    '内核重载代数是 ext 的关键前置条件，缺失应拒绝',
  )
})

test('ops：合法命令全部通过且 op 命名空间合法', () => {
  const defs = { app: opsSchema.$defs.appOps, ext: opsSchema.$defs.coreOps }
  for (const v of vectors.vectors.opsValid) {
    const props = defs[v.ch as keyof typeof defs].properties as Record<string, object>
    assert.ok(props[v.op], `${v.ch} 通道不应有未知 op：${v.op}`)
    // op 本身合法后，再单独校验它的 args
    const argsValidator = ajv.compile({ ...props[v.op] } as object)
    const args = payload(v.args ?? {})
    assert.ok(
      argsValidator(args),
      `${v.op} 的参数应合法：${ajv.errorsText(argsValidator.errors)}`,
    )
  }
})

test('ops：非法命令全部被拒', () => {
  const defs = { app: opsSchema.$defs.appOps, ext: opsSchema.$defs.coreOps }
  for (const v of vectors.vectors.opsInvalid) {
    const props = defs[v.ch as keyof typeof defs].properties as Record<string, object>
    // 两种非法形态：op 不存在，或 op 存在但参数不合法
    const opKnown = Boolean(props[v.op])
    const argsValidator = opKnown
      ? ajv.compile({ ...props[v.op] } as object)
      : null
    const accepted = opKnown
      ? Boolean(argsValidator?.(payload(v.args ?? {})))
      : false
    assert.ok(!accepted, `${v.op} 应被拒绝（${v.why}），但通过了`)
  }
})

test('ops：args 单独校验', () => {
  const appValidator = ajv.compile(opsSchema.$defs.appOps.properties['app.profile.add'])
  const extValidator = ajv.compile(opsSchema.$defs.coreOps.properties['core.mode.set'])
  assert.ok(appValidator({ url: 'https://example.com/sub' }), 'profile.add 最小参数')
  assert.ok(!appValidator({}), 'profile.add 缺 url')
  assert.ok(extValidator({ mode: 'rule' }), 'mode.set 合法值')
  assert.ok(!extValidator({ mode: 'turbo' }), 'mode.set 非法值')
})

test('路由：命名空间决定通道', () => {
  for (const r of vectors.vectors.routing) {
    assert.equal(routeOf(r.op), r.expectCh, `${r.op} 应路由到 ${r.expectCh}`)
  }
  assert.equal(routeOf('app.unknown'), 'app', '未知 app.* 仍属 app 通道（由能力协商拒绝）')
  assert.equal(routeOf('bogus'), null, '无命名空间前缀应无法路由')
})