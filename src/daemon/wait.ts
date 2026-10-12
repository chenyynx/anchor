/**
 * 命令等待：等待某条命令结算（带超时轮询）。
 * MCP 层的 hako_* 工具用它在「下发 → 设备应答」间同步等待。
 */
import type { OutboundQueue, QueueItem } from './queue'

export const waitForSettle = async (
  queue: OutboundQueue,
  id: string,
  timeoutMs = 15000,
  pollMs = 120,
): Promise<QueueItem> => {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const item = queue.get(id)
    if (!item) throw new Error(`命令不存在：${id}`)
    if (item.state !== 'queued' && item.state !== 'sent') return item
    if (Date.now() >= deadline) return item // 超时返回当前状态（sent/queued）
    await new Promise((r) => setTimeout(r, pollMs))
  }
}
