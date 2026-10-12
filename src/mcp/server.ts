/**
 * MCP 薄壳：把 daemon 能力暴露为 MCP 工具（stdio）。
 *
 * 设计原则（方案 v4 §MCP）：
 *   - 工具 = 一段 schema + 一个 handler（声明式，加工具不动机器）
 *   - 每个工具都是 daemon 状态的窄视图：无文件系统访问、无 shell、无任意参数透传
 *   - 错误回包带 hint（agent 自助修正），scope 不足明确拒
 *
 * 启动前提：daemon 已在跑（同进程或由 cli.ts 装配）。
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import type { Daemon } from '../daemon/daemon'
import { waitForSettle } from '../daemon/wait'
import type { Scopes } from '../daemon/registry'

/** 每工具的声明：name + 描述 + zod 参数 + handler */
interface ToolDef {
  name: string
  description: string
  schema: Record<string, z.ZodTypeAny>
  /** 需要设备具备的最低 scope */
  requires?: Scopes
  handler: (args: Record<string, unknown>, daemon: Daemon) => Promise<unknown>
}

const SCOPE_ORDER: Record<Scopes, number> = { observe: 0, operate: 1, manage: 2 }

/** 单设备模式：目前 daemon 一次管一台主控手机（多设备是 P1+） */
const primaryDevice = (daemon: Daemon): { devId: string; scopes: Scopes } | null => {
  const c = daemon.registry.controller() ?? daemon.registry.list()[0]
  if (!c) return null
  return { devId: c.dev_id, scopes: c.scopes }
}

const needDevice = (daemon: Daemon, requires: Scopes = 'observe'): { devId: string; scopes: Scopes } => {
  const d = primaryDevice(daemon)
  if (!d) {
    throw Object.assign(new Error('还没有已配对设备——先在手机上扫码配对（anchor pair）'), {
      hint: '运行 anchor pair 生成二维码，用 Hako App 扫码',
    })
  }
  if (d.scopes !== 'manage' && SCOPE_ORDER[d.scopes] < SCOPE_ORDER[requires]) {
    throw Object.assign(new Error(`设备 scope=${d.scopes}，本操作需要 ${requires}`), {
      hint: '在手机 App 的 Agent 管理页提升该 agent 的权限',
    })
  }
  return d
}

/** 下发 + 等结算，返回统一形状 */
const runCommand = async (
  daemon: Daemon,
  op: string,
  args: Record<string, unknown>,
  opts: { ch: 'app' | 'ext'; requires?: Scopes; timeoutMs?: number } = { ch: 'app' },
): Promise<unknown> => {
  const { devId } = needDevice(daemon, opts.requires)
  const sub = daemon.submitCommand({ devId, ch: opts.ch, op, args })
  if (!sub.ok) {
    // 幂等键重复：返回既有命令的结算结果
    const prev = daemon.queue.get(sub.id)
    if (prev && prev.state !== 'queued' && prev.state !== 'sent') {
      return { status: prev.state, data: prev.result, err: prev.err }
    }
  }
  const item = await waitForSettle(daemon.queue, sub.id, opts.timeoutMs ?? 15000)
  if (item.state === 'rejected') {
    const err = (item.err ?? {}) as { code?: string; message?: string; hint?: string }
    throw Object.assign(new Error(err.message ?? '设备拒绝'), {
      code: err.code,
      hint: err.hint,
    })
  }
  if (item.state === 'sent' || item.state === 'queued') {
    throw Object.assign(new Error(`设备未在时限内应答（当前状态 ${item.state}）`), {
      hint: '设备可能离线或锁屏；确认手机在线后重试',
      retryable: true,
    })
  }
  return { status: item.state, data: item.result }
}

/* ---------------- 工具清单（13 个）---------------- */

const TOOLS: ToolDef[] = [
  // 状态观察（observe）
  {
    name: 'hako_status',
    description: '查看 Hako 运行状态：VPN 开关、当前节点/模式、订阅概况、设备在线情况',
    schema: {},
    handler: async (_a, d) => {
      const { devId } = needDevice(d)
      const dev = d.registry.get(devId)!
      return {
        device: { id: devId, alias: dev.alias, online: d.sessions.isOnline(devId), scopes: dev.scopes },
        runtime: await runCommand(d, 'app.state.get', {}, { ch: 'app' }),
      }
    },
  },
  {
    name: 'hako_proxies',
    description: '列出代理节点/策略组（可按订阅过滤），返回节点名、类型、延迟',
    schema: { subscription: z.string().optional().describe('按订阅 ID/名称过滤') },
    handler: async (a, d) => runCommand(d, 'app.proxy.list', a, { ch: 'app' }),
  },
  {
    name: 'hako_proxy_delay',
    description: '测指定节点/策略组的延迟（经隧道真实探测）',
    schema: {
      targets: z.array(z.string()).min(1).describe('节点名或策略组名'),
      timeout_ms: z.number().int().min(1000).max(10000).optional(),
    },
    handler: async (a, d) => runCommand(d, 'core.proxy.delay', a, { ch: 'ext' }),
  },
  // VPN 控制（operate）
  {
    name: 'hako_vpn',
    description: '开/关 VPN 隧道。action=on|off；首次开启若系统弹窗，会返回 NEED_USER_ACTION 提示',
    schema: { action: z.enum(['on', 'off']) },
    requires: 'operate',
    handler: async (a, d) =>
      runCommand(d, a.action === 'on' ? 'app.vpn.start' : 'app.vpn.stop', {}, { ch: 'app', requires: 'operate' }),
  },
  {
    name: 'hako_mode',
    description: '设置出站模式：rule=规则 / global=全局 / direct=直连',
    schema: { mode: z.enum(['rule', 'global', 'direct']) },
    requires: 'operate',
    handler: async (a, d) => runCommand(d, 'core.mode.set', a, { ch: 'ext', requires: 'operate' }),
  },
  {
    name: 'hako_select',
    description: '在策略组中选择节点',
    schema: { group: z.string().describe('策略组名'), proxy: z.string().describe('节点名') },
    requires: 'operate',
    handler: async (a, d) => runCommand(d, 'core.proxy.select', a, { ch: 'ext', requires: 'operate' }),
  },
  // 订阅管理（operate/manage）
  {
    name: 'hako_profile_list',
    description: '列出全部订阅（配置档案）：名称、URL、节点数、更新时间',
    schema: {},
    handler: async (_a, d) => runCommand(d, 'app.profile.list', {}, { ch: 'app' }),
  },
  {
    name: 'hako_profile_add',
    description: '添加订阅（URL 方式）。add 后建议调用 hako_profile_select 启用',
    schema: {
      url: z.string().url().describe('订阅链接'),
      name: z.string().max(64).optional(),
    },
    requires: 'manage',
    handler: async (a, d) => runCommand(d, 'app.profile.add', a, { ch: 'app', requires: 'manage' }),
  },
  {
    name: 'hako_profile_select',
    description: '切换启用某订阅',
    schema: { id: z.string().describe('订阅 ID（来自 hako_profile_list）') },
    requires: 'operate',
    handler: async (a, d) => runCommand(d, 'app.profile.select', a, { ch: 'app', requires: 'operate' }),
  },
  {
    name: 'hako_profile_update',
    description: '更新订阅（拉取远端最新配置）',
    schema: { id: z.string().optional().describe('订阅 ID；缺省更新全部') },
    requires: 'operate',
    handler: async (a, d) => runCommand(d, 'app.profile.update', a, { ch: 'app', requires: 'operate' }),
  },
  {
    name: 'hako_profile_remove',
    description: '删除订阅',
    schema: { id: z.string() },
    requires: 'manage',
    handler: async (a, d) => runCommand(d, 'app.profile.remove', a, { ch: 'app', requires: 'manage' }),
  },
  {
    name: 'hako_rules',
    description: '查看分流规则统计（命中/条数），可选按策略过滤',
    schema: {},
    handler: async (_a, d) => runCommand(d, 'core.rules.get', {}, { ch: 'ext' }),
  },
  {
    name: 'hako_connections',
    description: '查看当前活跃连接（应用/目标/规则/链路），支持按关键字过滤',
    schema: { filter: z.string().optional() },
    handler: async (a, d) => runCommand(d, 'core.connections.get', a, { ch: 'ext' }),
  },
]

/* ---------------- 装配 ---------------- */

export const buildMcpServer = (daemon: Daemon): McpServer => {
  const server = new McpServer(
    { name: 'anchor', version: '0.0.0' },
    { instructions: 'Hako 客户端远程管理。设备离线时工具会报错——让用户先打开手机上的 Hako App。' },
  )

  for (const t of TOOLS) {
    server.tool(t.name, t.description, t.schema, async (args) => {
      try {
        const data = await t.handler((args ?? {}) as Record<string, unknown>, daemon)
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (e) {
        const err = e as Error & { hint?: string; code?: string; retryable?: boolean }
        const lines = [`错误：${err.message}`]
        if (err.code) lines.push(`code: ${err.code}`)
        if (err.hint) lines.push(`hint: ${err.hint}`)
        return {
          isError: true,
          content: [{ type: 'text', text: lines.join('\n') }],
        }
      }
    })
  }

  return server
}

export const runMcpStdio = async (daemon: Daemon): Promise<void> => {
  const server = buildMcpServer(daemon)
  await server.connect(new StdioServerTransport())
  // stdio 模式：进程常驻直到 stdin 关闭
}
