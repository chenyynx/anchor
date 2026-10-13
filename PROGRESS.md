# Anchor 项目进度总览（2026-10-13 快照）

## 已完成：P0 ✅（agent 端全闭环，53 测试全绿，CI 绿，仓库公开）

## 剩余工作

### P1 — HakoAgentKit + EC（手机端会说"这门语言"）
| 任务 | 规模估计 |
|---|---|
| SwiftPM 纯逻辑包：信封编解码 / Noise_XX via CryptoKit / 状态机 / 退避 / 去重表 | 大头：Noise 互验逐字节对齐 |
| swift test 跑通 P0 全部测试向量 | 向量机制现成，落 Swift 即可 |
| EC 接 clash.sock 实现 core.*（胶水 ≤200 行，内核零改动） | 小，仿 WidgetMailboxService |
| 内存预算 ≤3MB / CI（swift test on macOS runner） | 小 |

**估：1-2 个工作日**（配合 CI 反复跑）

### P2 — 配对 + AC + UI（能用起来）
| 任务 | 规模 |
|---|---|
| 首页 Agent 卡 + 二级页（UI 已定稿，文件级搬运官方组件） | 中 |
| 扫码 / 粘贴 / Bonjour 三路配对 + Keychain 共享组 | 中 |
| AC（前台在线连接器）+ app.vpn.* / app.profile.* | 中 |
| 设置页 + 操作记录基础版 | 小 |
| **真机验证**（扫码相机、权限弹窗）| 必须 pp 参与 |

**估：2-3 个工作日**

### P3 — 配置管理与安全回滚（安全底线）
- overlay 落 OverridePatch / patch-apply-confirm-rollback / 直连规则置顶 / mailbox v2 HMAC / 一键撤销
- **估：1-2 个工作日**

### P4 — 后台可达（零操作体验）
- Wake Gateway（无状态组件）+ APNs 静默推送 + On-Demand 规则 + deferred 完整落地
- **⚠️ APNs 需要发布方账号（pp 的开发者账号密钥）**
- **估：1-2 个工作日 + 真机 spike**

### P5 — 产品化与开源（给别人用）
- 文档站 / 错误文案全表+本地化 / 威胁建模 / 中继参考实现 / 上游同步流水线 / npm 发布决策
- **估：1-2 个工作日**

## 总账
- **剩余 ≈ 6-11 个专注工作日**（理想连续推进）
- 里程碑：M1✅ → M2 = P2 完（前台体验）→ M3 = P4 完（零操作）
- 依赖 pp 的点：P2 真机验证、P4 APNs 密钥、P5 品牌决策（npm 包名已定 scope 方向）
