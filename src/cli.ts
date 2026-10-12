#!/usr/bin/env tsx
/**
 * anchor CLI。
 *
 * 命令：
 *   pair       生成配对窗口（二维码 + 口令 URI）
 *   daemon     启动常驻服务（WS 监听）
 *   mcp        启动 MCP 薄壳（stdio；需 daemon 已运行，或与 daemon 同进程 --with-daemon）
 *   devices    列出已配对设备
 *   export-identity / import-identity
 *
 * 约定：ANCHOR_HOME 状态目录（默认 ~/.anchor）。
 */
import { homedir, hostname } from 'node:os'
import { readFileSync } from 'node:fs'
import { createPrivateKey } from 'node:crypto'
import { join } from 'node:path'
import QRCode from 'qrcode'
import { loadOrCreateIdentity, parseIdentityFile, saveIdentity } from './daemon/identity'
import { PairingWindows, b64url } from './daemon/pairing'
import { openDb } from './daemon/db'
import { Registry } from './daemon/registry'
import { Daemon } from './daemon/daemon'
import { runMcpStdio } from './mcp/server'

const home = process.env.ANCHOR_HOME ?? join(homedir(), '.anchor')

const HELP = `anchor — Hako 控制面的 agent 端程序
用法：anchor <命令> [参数]
命令：
  pair [--endpoint <url>]     生成配对窗口（二维码 + 口令 URI）
  daemon [--port N] [--host H] 启动常驻服务
  mcp [--with-daemon] [--port N] MCP 壳（stdio；--with-daemon 同进程拉起 daemon）
  devices                     列出已配对设备
  export-identity             导出身份（含私钥，注意保管）
  import-identity <file>      从导出文件恢复身份
`

const flag = (args: string[], name: string): string[] => {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1]) out.push(args[i + 1]!)
  }
  return out
}

const hasFlag = (args: string[], name: string): boolean => args.includes(name)

/** 从身份构造 X25519 DHKey（identity 存的是 PEM，运行时转 KeyObject） */
const dhKeyFromIdentity = (ident: ReturnType<typeof loadOrCreateIdentity>['ident']) => {
  const f = ident.toFile()
  const priv = createPrivateKey(f.keys.x25519.private_pem)
  return { priv, pub: ident.xPubRaw }
}

const main = async (): Promise<void> => {
  const [cmd = 'help', ...rest] = process.argv.slice(2)

  switch (cmd) {
    case 'pair': {
      const { ident, created } = loadOrCreateIdentity(home)
      const endpoints = flag(rest, '--endpoint')
      const port = flag(rest, '--port')[0] ?? '8787'
      const eps = endpoints.length > 0 ? endpoints : [`ws://${hostname()}:${port}/ws`]
      const win = new PairingWindows().open({
        k: b64url(ident.xPubRaw),
        endpoints: eps,
        name: hostname(),
      })
      console.log(`${created ? '已生成新身份' : '身份'} ${ident.agentId}（home: ${home}）`)
      console.log(`\n${win.uri}\n`)
      console.log(await QRCode.toString(win.uri, { type: 'terminal', small: true }))
      console.log(`窗口 ${Math.round((win.expires_at - Date.now()) / 1000)}s 内有效。`)
      console.log('注：请先启动 daemon（anchor daemon），否则扫码后设备连不上。')
      break
    }

    case 'daemon': {
      const { ident } = loadOrCreateIdentity(home)
      const port = Number(flag(rest, '--port')[0] ?? 8787)
      const host = flag(rest, '--host')[0] ?? '0.0.0.0'
      const daemon = new Daemon({
        db: openDb(join(home, 'state.db')),
        staticKey: dhKeyFromIdentity(ident),
        port,
        host,
        onLog: (l) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${l}`),
      })
      await daemon.listen()
      console.log(`anchor daemon 监听 ${host}:${port}（agent ${ident.agentId}）`)
      console.log('Ctrl+C 退出。配对：另开终端运行 anchor pair')
      const stop = (): void => {
        daemon.close()
        process.exit(0)
      }
      process.on('SIGINT', stop)
      process.on('SIGTERM', stop)
      break
    }

    case 'mcp': {
      const withDaemon = hasFlag(rest, '--with-daemon')
      const port = Number(flag(rest, '--port')[0] ?? 8787)
      let daemon: Daemon
      if (withDaemon) {
        const { ident } = loadOrCreateIdentity(home)
        daemon = new Daemon({
          db: openDb(join(home, 'state.db')),
          staticKey: dhKeyFromIdentity(ident),
          port,
          host: '127.0.0.1',
          onLog: () => {}, // stdio 模式下日志走 stderr 会污染 MCP 通道，静默
        })
        await daemon.listen()
        console.error(`[anchor] daemon 同进程启动（127.0.0.1:${port}）`)
      } else {
        // 连接既有 daemon：P0 简化为同机直开同一 SQLite（状态共享）
        daemon = new Daemon({
          db: openDb(join(home, 'state.db')),
          staticKey: dhKeyFromIdentity(loadOrCreateIdentity(home).ident),
          port: 0, // 不监听
        })
        console.error('[anchor] MCP 壳共享状态目录（daemon 需另行运行）')
      }
      await runMcpStdio(daemon)
      break
    }

    case 'devices': {
      const reg = new Registry(openDb(join(home, 'state.db')))
      const list = reg.list()
      if (list.length === 0) {
        console.log('（还没有已配对设备）')
        break
      }
      for (const d of list) {
        const marks = `${d.is_controller ? '  [主控]' : ''}${d.revoked_at ? '  [已撤销]' : ''}`
        console.log(`${d.dev_id}  ${d.alias ?? '-'}  scopes=${d.scopes}${marks}`)
      }
      break
    }

    case 'export-identity': {
      const { ident } = loadOrCreateIdentity(home)
      console.error('警告：以下内容含私钥，只应保存到可信位置。')
      console.log(JSON.stringify(ident.toFile(), null, 2))
      break
    }

    case 'import-identity': {
      const [file] = rest
      if (!file) {
        console.error('用法：anchor import-identity <file.json>')
        process.exitCode = 1
        break
      }
      const ident = parseIdentityFile(readFileSync(file, 'utf8'))
      saveIdentity(home, ident)
      console.log(`已恢复身份 ${ident.agentId} → ${home}`)
      break
    }

    default:
      console.log(HELP)
  }
}

main().catch((e: unknown) => {
  const err = e as Error & { hint?: string }
  console.error(`错误：${err.message}`)
  if (err.hint) console.error(`提示：${err.hint}`)
  process.exitCode = 1
})
