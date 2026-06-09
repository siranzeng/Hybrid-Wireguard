# Hybrid-WireGuard 功能实现审计辅助文档

审查日期：2026-06-07

本文档用于帮助人工审计员调查当前仓库的功能实现情况。它不是安全证明，也不是最终验收结论；重点是说明实现入口、已修复缺陷、可复核证据、验证结果和仍需人工确认的风险点。

## 1. 审查范围

| 实现族 | 选择方式 | 主要目录 | 当前状态 |
| --- | --- | --- | --- |
| Original WireGuard | 默认，无 feature | `src/wireguard/`、`src/configuration/` | 已接入入口，`cargo check` 通过 |
| PQ-WireGuard* | `--features post_quantum` | `src/wireguard_pq_star/`、`src/configuration_pq_star/` | 已接入入口，`cargo check --features post_quantum` 通过 |
| Hybrid WireGuard V1 | `--features hybrid` | `src/wireguard_hybrid/`、`src/configuration_hybrid/` | 已接入入口，`cargo check --features hybrid` 通过 |
| Hybrid WireGuard V2.3 | `--features hybrid_new` | `src/wireguard_hybrid_new/`、复用 `src/configuration_hybrid/` | 已接入入口，`cargo check --features hybrid_new` 通过 |

入口证据：

- `src/main.rs:5-9`：`hybrid`、`hybrid_new`、`post_quantum` 互斥。
- `src/main.rs:50-74`：按 feature 切换配置模块和 WireGuard 实现。
- `src/main.rs:78-99`：无协议 feature 时使用原始 WireGuard。
- `src/configuration_hybrid_new/mod.rs:1`：V2.3 配置模块重导出 `configuration_hybrid`，实际差异由 `#[cfg(feature = "hybrid_new")]` 切换。

## 2. 本轮已修复缺陷

### 2.1 V2.3 Cookie 前置门控顺序

修复前，低压状态下的无 Cookie InitHello 会进入 `consume_initiation_first_part`，在 peer 级 `mac1` 校验和 IP rate limiter 之前执行静态 KEM 解封装。该顺序与 V2.3 文档中“未通过 Cookie/MAC 准入前不做昂贵处理”的目标不一致。

修复后：

- `src/wireguard_hybrid_new/handshake/device.rs:990-1038`：对真实 UDP 来源 `src=Some(...)`，先执行梯度 DoS 预检查，再要求有效 Cookie；无 Cookie 时直接返回 `CookieReply`，不进入静态 KEM 解封装。
- `src/wireguard_hybrid_new/handshake/tests.rs:184-218`：新增测试覆盖“带来源地址的 InitHello 必须先拿 Cookie，携带有效 Cookie 后才产生握手响应”。

人工复核要点：

- 确认 `src=None` 只用于内部或测试路径；真实网络路径必须传入 `SocketAddr`。
- 确认协议标准是否允许低压首包也强制 Cookie；当前实现选择优先满足“昂贵处理前准入”的 V2.3 DoS 目标。

### 2.2 V2.3 网络输入 panic 风险

修复前，V2.3 报文处理路径对对端可控的 OQS public key/ciphertext/decapsulation 多处使用 `unwrap()`。畸形 InitHello 或 RespHello 可能触发进程 panic。

修复后：

- `src/wireguard_hybrid_new/handshake/noise.rs:587-592`：InitHello 静态 KEM ciphertext 解析和解封装失败返回 `HandshakeError::DecryptionFailure`。
- `src/wireguard_hybrid_new/handshake/noise.rs:672-692`：InitHello ephemeral PQ public key 和 ratchet ciphertext 解析失败返回握手错误。
- `src/wireguard_hybrid_new/handshake/noise.rs:955-988`：RespHello ephemeral/static KEM ciphertext 解析和解封装失败返回握手错误。

人工复核要点：

- 对 `Initiation::parse` 和 `Response::parse` 后的消息结构做畸形字段 fuzz，确认返回错误而不是 panic。
- 内部生成密钥后的尺寸 `try_from(...).unwrap()` 仍保留，这类路径不是网络可控输入；如需更严格容错，可另行统一错误处理。

### 2.3 UAPI `protocol_version` 提交顺序和错误传播

修复前，三套 UAPI parser 会在检查 `protocol_version` 前先提交 peer、allowed IP、PSK、endpoint 等状态；即使发现版本不支持，错误也可能被调用点忽略。

修复后：

- `src/configuration/uapi/set.rs:64-89`：先验证 `protocol_version`，再提交 peer 变更；`flush_peer` 返回 `Result`。
- `src/configuration_hybrid/uapi/set.rs:91-120`：Hybrid/V2.3 同步修复。
- `src/configuration_pq_star/uapi/set.rs:75-101`：PQ-WireGuard* 同步修复。
- `src/configuration/uapi/set.rs:175`、`src/configuration_hybrid/uapi/set.rs:257`、`src/configuration_pq_star/uapi/set.rs:219`：切换 peer 时传播 `flush_peer(...)` 错误。
- `src/configuration/uapi/set.rs:255`、`src/configuration_hybrid/uapi/set.rs:337`、`src/configuration_pq_star/uapi/set.rs:299`：输入结束时传播 `flush_peer(...)` 错误。

人工复核要点：

- 构造包含不支持 `protocol_version` 的 UAPI transcript，确认命令返回错误且设备状态不被部分提交。
- 检查 `version == 0` 和 `version > get_protocol_version()` 两类边界。

### 2.4 UAPI `replace_allowed_ips=true`

修复前，parser 只清空本地解析缓存，没有调用配置层 `replace_allowed_ips(...)`，旧路由可能残留。

修复后：

- `src/configuration/uapi/set.rs:83-86`：原始 WireGuard 配置提交时清理旧 allowed IP。
- `src/configuration_hybrid/uapi/set.rs:114-118`：Hybrid/V2.3 配置提交时按 peer hash 清理旧 allowed IP。
- `src/configuration_pq_star/uapi/set.rs:96-99`：PQ-WireGuard* 配置提交时按 peer hash 清理旧 allowed IP。

人工复核要点：

- 对同一 peer 先设置两个 allowed IP，再发送 `replace_allowed_ips=true` 和一个新 allowed IP，确认旧路由被删除。
- 覆盖 peer 分段切换和输入结束两条 flush 路径。

### 2.5 UAPI 畸形 PQ key 输入

修复前，Hybrid/PQ 的 UAPI 外部输入解析对 hex、数组长度和 OQS key conversion 使用多个 `unwrap()`。

修复后：

- `src/configuration_hybrid/uapi/set.rs:53-65`：Hybrid/V2.3 peer public key 解析失败返回 `ConfigError::InvalidHexValue`。
- `src/configuration_hybrid/uapi/set.rs:161-193`：Hybrid/V2.3 private key 解析失败返回 `ConfigError::InvalidHexValue`。
- `src/configuration_pq_star/uapi/set.rs:43-50`：PQ peer public key 解析失败返回 `ConfigError::InvalidHexValue`。
- `src/configuration_pq_star/uapi/set.rs:140-168`：PQ private key 解析失败返回 `ConfigError::InvalidHexValue`。

人工复核要点：

- 构造短 hex、奇数长度 hex、超长 hex、随机 McEliece public/secret key 字节，确认 UAPI 返回错误且进程不 panic。

### 2.6 UAPI 行长度限制

修复前，Hybrid/PQ UAPI `MAX_LINE_LENGTH = 256`，无法容纳 Classic-McEliece-460896 public/private key 的 hex 文本。

修复后：

- `src/configuration_hybrid/uapi/mod.rs:20-21`：Hybrid/V2.3 按 X25519、静态 KEM secret key、静态 KEM public key 总长度计算 `private_key=` 行上限。
- `src/configuration_pq_star/uapi/mod.rs:14-15`：PQ-WireGuard* 按静态 KEM secret/public key 总长度计算 `private_key=` 行上限。

人工复核要点：

- 使用真实 `get=1` 输出作为 `set=1` 输入回放，确认 private/public key 行不会被截断。
- 对极长非法行确认仍有上限保护，不会无限增长。

## 3. 已执行验证

在当前 Windows/MSVC 环境执行：

```powershell
cargo fmt
cargo check
cargo check --features hybrid
cargo check --features post_quantum
cargo check --features hybrid_new
```

结果：以上命令均通过。

执行新增 V2.3 测试：

```powershell
cargo test --features hybrid_new initiation_with_source_requires_cookie_before_expensive_processing -- --nocapture
```

结果：测试二进制未完成链接，未进入测试执行阶段。失败原因是本机 OpenSSL 链接依赖缺失：

```text
LINK : fatal error LNK1181: cannot open input file "libcrypto.lib"
```

人工验收应在 README 指定或等效的完整构建环境中重新执行：

```bash
cargo test
cargo test --features hybrid
cargo test --features post_quantum
cargo test --features hybrid_new
```

## 4. V2.3 实现证据索引

算法和参数：

- `src/wireguard_hybrid_new/handshake/crypto_params.rs:6-17`：ML-KEM-512 用于 ephemeral/ratchet KEM。
- `src/wireguard_hybrid_new/handshake/crypto_params.rs:37-40`：Classic-McEliece-460896 用于静态 KEM，public key 长度 524160 字节。
- `src/wireguard_hybrid_new/handshake/messages.rs:34-36`：`MODE_BOOTSTRAP`、`MODE_RATCHET`、`MODE_RESYNC`。

消息结构和尺寸：

- `src/wireguard_hybrid_new/handshake/messages.rs:62-74`：`NoiseInitiation` 字段。
- `src/wireguard_hybrid_new/handshake/messages.rs:79-90`：`NoiseResponse` 字段。
- `src/wireguard_hybrid_new/handshake/tests.rs:258-268`：当前断言 `Initiation = 2004`、`Response = 2012`、`CookieReply = 92`，并确认握手包加 IPv6/UDP 开销后超过 1280。

握手流程：

- `src/wireguard_hybrid_new/handshake/noise.rs:387-535`：发起方创建 InitHello。
- `src/wireguard_hybrid_new/handshake/device.rs:990-1094`：响应方处理 InitHello，包括 Cookie gate、MAC/rate limit、两阶段解析和响应生成。
- `src/wireguard_hybrid_new/handshake/noise.rs:538-714`：响应方解析 InitHello。
- `src/wireguard_hybrid_new/handshake/noise.rs:722-859`：响应方创建 RespHello。
- `src/wireguard_hybrid_new/handshake/noise.rs:864-1065`：发起方处理 RespHello。

DoS、Cookie 和重放：

- `src/wireguard_hybrid_new/handshake/device.rs:337-421`：梯度 DoS 预检查、token bucket、行为触发、半开连接配额。
- `src/wireguard_hybrid_new/handshake/device.rs:498-516`：半开连接登记和成功完成后的清理。
- `src/wireguard_hybrid_new/handshake/peer.rs:462-491`：`k_received` 单调计数和 20ms initiation flood 检查。
- `src/wireguard_hybrid_new/handshake/macs.rs:94-105`、`src/wireguard_hybrid_new/handshake/macs.rs:167-187`：MAC1 key 与 PSK 绑定。

## 5. 仍需人工确认的事项

1. V2.3 文档和源码的消息尺寸是否一致。源码当前握手包尺寸与旧差异说明中的 1140/1080 字节不一致，应以最终协议标准重新生成消息尺寸表。
2. 许可元数据不一致：`README.md` 声明 GNU GPL v3，`Cargo.toml` 声明 MIT，发布前需要统一。
3. 编译仍有既有 warning：`feature = "unstable"` 未在 `Cargo.toml` 声明，多处 `#[cfg(debug)]` 应改为 `#[cfg(debug_assertions)]` 或显式声明 cfg。
4. 本机未运行单元测试，原因是 `libcrypto.lib` 缺失；需要在具备 OpenSSL/liboqs 链接环境的机器上跑全量测试。
5. 建议补充自动化 UAPI 状态机测试，覆盖 `protocol_version`、`replace_allowed_ips`、畸形 PQ key 和多 peer flush 边界。
6. 建议补充畸形 UDP 报文 fuzz，覆盖 V2.3 InitHello/RespHello 的 KEM public key、ciphertext、encrypted identity、confirm 和 auth 字段。

## 6. 人工审计建议路径

1. 先确认协议基线：以 `Hybrid-WireGuard_协议V2.3.docx` 为准，标记与 `diff.md` 的差异。
2. 再确认 feature 选择：检查 `Cargo.toml:53-58` 和 `src/main.rs:5-99`，确保运行时进入待审实现族。
3. 对 V2.3 优先审查 DoS 顺序：从 `Device::process` 到 `consume_initiation_first_part`，确认 Cookie/MAC、rate limiter、peer lookup、静态 KEM 解封装的先后关系符合标准。
4. 对配置层做状态机测试：构造 UAPI transcript，验证 peer 添加、更新、删除、`replace_allowed_ips`、`protocol_version`、PSK、endpoint 的提交顺序。
5. 对网络输入做 panic/fuzz 测试：重点覆盖 `messages.rs` 解析后的 KEM `from_bytes/decapsulate` 路径。
6. 最后在目标环境跑全量测试和 benchmark，记录 Rust、MSVC/Clang、OpenSSL、liboqs 版本。
