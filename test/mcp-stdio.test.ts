/**
 * MCP stdio 真实传输测试：spawn `anchor mcp --with-daemon` 子进程，
 * 按 MCP JSON-RPC 协议走 initialize → tools/list → tools/call。
 * 这是 P0 验收「Claude Code 真实调用」的等价通路（同一 stdio 协议）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')

interface JsonRpcMsg {
  jsonrpc: '2.0'
  id?: number
  method?: string
  params?: Record<string, unknown>
  result?: Record<string, unknown>
  error?: { code: number; message: string }
}

class McpClient {
  #proc
  #buf = ''
  #nextId = 1
  #pending = new Map<number, (m: JsonRpcMsg) => void>()

  constructor(env: Record<string, string>) {
    // 直接以 node + tsx CLI 入口运行，避免 npx 的 npm 解析层（启动快且 stderr 干净）
    this.#proc = spawn(process.execPath, ['node_modules/tsx/dist/cli.mjs', 'src/cli.ts', 'mcp', '--with-daemon', '--port', '19777'], {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    // 吞掉 stderr（npm/tsx 噪音会拖慢管道），只保留少量用于调试
    this.#proc.stderr!.on('data', (d: Buffer) => {
      this.stderr = (this.stderr + d.toString()).slice(-500)
    })
    this.#proc.stdout!.on('data', (chunk: Buffer) => {
      this.#buf += chunk.toString('utf8')
      // MCP stdio = 换行分隔 JSON
      let idx: number
      while ((idx = this.#buf.indexOf('\n')) >= 0) {
        const line = this.#buf.slice(0, idx).trim()
        this.#buf = this.#buf.slice(idx + 1)
        if (!line) continue
        try {
          const msg = JSON.parse(line) as JsonRpcMsg
          if (msg.id && this.#pending.has(msg.id)) {
            this.#pending.get(msg.id)!(msg)
            this.#pending.delete(msg.id)
          }
        } catch {
          /* 非 JSON 行忽略 */
        }
      }
    })
    this.#proc.stderr!.on('data', (d: Buffer) => {
      // 收集用于调试（截尾，防 npm 噪音无限增长）
      this.stderr = (this.stderr + d.toString()).slice(-800)
    })
  }

  stderr = ''

  request(method: string, params: Record<string, unknown>, timeoutMs = 30000): Promise<JsonRpcMsg> {
    const id = this.#nextId++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id)
        reject(new Error(`${method} 超时（stderr: ${this.stderr.slice(-200)}）`))
      }, timeoutMs)
      this.#pending.set(id, (m) => {
        clearTimeout(timer)
        resolve(m)
      })
      this.#proc.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    })
  }

  notify(method: string, params: Record<string, unknown>): void {
    this.#proc.stdin!.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`)
  }

  close(): void {
    this.#proc.kill('SIGTERM')
  }
}

test('MCP stdio：initialize → tools/list（13 工具）→ tools/call', async () => {
  const home = mkdtempSync(join(tmpdir(), 'hako-mcp-'))
  const c = new McpClient({ ANCHOR_HOME: home })
  try {
    // initialize
    const init = await c.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'test-client', version: '0.0.0' },
    })
    assert.equal(init.result?.serverInfo?.name, 'anchor')
    c.notify('notifications/initialized', {})

    // tools/list
    const list = await c.request('tools/list', {})
    const tools = (list.result?.tools ?? []) as { name: string }[]
    assert.equal(tools.length, 13, `应有 13 个工具，实际 ${tools.length}`)
    const names = tools.map((t) => t.name)
    for (const expect of ['hako_status', 'hako_vpn', 'hako_profile_add', 'hako_connections']) {
      assert.ok(names.includes(expect), `缺少工具 ${expect}`)
    }

    // tools/call：无设备时应返回带 hint 的错误（而不是崩溃/超时）
    const call = await c.request('tools/call', {
      name: 'hako_status',
      arguments: {},
    })
    assert.equal(call.result?.isError, true, '无设备时 hako_status 应报错')
    const text = (call.result?.content as { text: string }[])[0]?.text ?? ''
    assert.match(text, /还没有已配对设备/)
    assert.match(text, /hint:/)
  } finally {
    c.close()
  }
})
