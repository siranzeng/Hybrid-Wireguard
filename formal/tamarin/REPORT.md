# Hybrid-WireGuard V2.3 Tamarin 符号安全证明报告

## 1. 摘要

本报告说明 `formal/tamarin/hybrid_wireguard_v23.spthy` 中的 Tamarin 模型和证明目标。模型针对 Hybrid-WireGuard V2.3 的真实网络握手路径，即实现中 `src=Some(...)` 的路径；测试或内部调用路径 `src=None` 不纳入 DoS gate 结论。

模型采用符号化攻击者观察模型：攻击者通过 `Out(...)` 观察全部握手网络消息，不能破坏被建模为理想构造子的密码原语。协议状态转换使用“已解析/已验证消息”的内部 facts 表达，以避免在 Tamarin 中对 KEM ciphertext、MAC、Cookie 等不透明构造子做不可靠的自定义模式匹配。X25519、ML-KEM、Classic-McEliece、AEAD、MAC、hash/KDF 均按完美符号原语抽象处理。

本证明覆盖以下目标：

- 会话密钥保密。
- 发起方和响应方的双向认证与会话参数一致性。
- 响应方接受的 initiation counter 不可重复。
- V2.3 response confirm 绑定 `next(epoch)` 与派生的 next kid。
- 在真实网络路径中，`CookieValid` 必须严格先于 `StaticKemDecap`。

本报告不声称证明 Rust 实现级内存安全、liboqs 正确性、具体算法的计算安全归约、侧信道安全或 DoS 策略的资源上界。

## 2. 模型说明

Tamarin 文件：`formal/tamarin/hybrid_wireguard_v23.spthy`

模型将 V2.3 握手抽象为以下阶段：

1. `Setup_Pair`：建立一对 peer 的静态 DH/KEM 公钥、PSK、Cookie secret 和初始 ratchet root。
2. `Initiator_Send_No_Cookie`：发起方在真实网络路径发送无 Cookie 的首个 InitHello，并通过 `Out(...)` 暴露给攻击者观察。
3. `Responder_Send_CookieReply`：响应方只返回 CookieReply，不进入静态 KEM 解封装。
4. `Initiator_Send_With_Cookie`：发起方携带 Cookie 和 MAC 重发 InitHello，并触发 `InitRunning`。
5. `Responder_Validate_Cookie_And_Mac`：抽象响应方完成 Cookie/MAC 验证，触发 `CookieValid`。
6. `Responder_StaticKem_And_Response`：响应方在已验证 Cookie/MAC 后执行静态 KEM 解封装，触发 `StaticKemDecap`、`AcceptCounter`、`RCommit` 和 `ConfirmBind`。
7. `Initiator_Consume_Response`：发起方验证 response confirm 后触发 `ICommit`。

关键 action facts：

- `InitRunning(I, R, k, sid_i, epoch, counter)`：发起方发送带 Cookie 的有效 InitHello。
- `CookieValid(R, I, src, sid_i, body)`：响应方已验证同源 Cookie。
- `StaticKemDecap(R, I, src, sid_i, ct)`：响应方执行静态 KEM 解封装。
- `AcceptCounter(I, R, counter)`：响应方接受一个 initiation counter。
- `RCommit(...)` / `ICommit(...)`：响应方/发起方完成握手并确认同一会话参数。
- `ConfirmBind(...)`：response confirm 中携带的 next epoch 和 next kid 绑定事件。

## 3. 证明目标

`protocol_executable`

证明模型存在一条完整握手轨迹，避免安全 lemma 在空模型上真。

`session_key_secrecy`

若发起方完成 `ICommit`，攻击者不能获得对应会话密钥 `k`。

`responder_agreement`

若响应方完成 `RCommit`，则此前存在对应的发起方 `InitRunning`，且会话密钥、发起方会话 ID、epoch 和 counter 一致。

`initiator_agreement`

若发起方完成 `ICommit`，则此前存在对应的响应方 `RCommit`，且双方会话密钥、会话 ID、epoch、next epoch、next kid 和 counter 一致。

`initiator_injective_agreement`

同一组发起方完成参数不能对应两个不同的 `ICommit` 事件。

`responder_counter_replay_rejected`

同一 `(I, R, counter)` 不能被响应方接受两次。模型用 `UniqueCounterAcceptance` restriction 表达实现中的 replay cache 约束。

`cookie_gate_before_static_kem`

任意 `StaticKemDecap` 事件之前，必须存在严格更早的同源、同会话 `CookieValid` 事件。该 lemma 对应 V2.3 的 DoS 目标：未通过 Cookie/MAC 准入前不执行昂贵静态 KEM 处理。

`response_confirm_binds_next_ratchet`

任意 response confirm 必须绑定 `next(epoch)` 和 `kid(rk, next(epoch), next_pub)`。

## 4. 运行方式

本工作区使用 Docker 构建 Tamarin，避免依赖 Windows 原生安装。Dockerfile 从 Tamarin 官方仓库 tag `1.12.0` 构建。

如果需要从 Dockerfile 构建默认镜像，在仓库根目录运行：

```powershell
.\formal\tamarin\run_docker.ps1
```

本次验证使用本机已有镜像 `tamarin:init`，运行命令为：

```powershell
.\formal\tamarin\run_docker.ps1 -NoBuild -Image tamarin:init
```

脚本证明阶段执行等价于：

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace tamarin:init `
  tamarin-prover --derivcheck-timeout=60 --prove formal/tamarin/hybrid_wireguard_v23.spthy
```

输出文件：

- `formal/tamarin/results/tamarin-version.txt`
- `formal/tamarin/results/tamarin-proof.txt`

验收标准：`tamarin-proof.txt` 中所有安全 lemma 必须显示为 verified。任何未证明 lemma 都必须在本报告中标为未完成，不能写成已证明结论。

## 5. 当前证明状态

已使用 Docker 镜像 `tamarin:init` 完成 Tamarin batch proof。版本记录见 `formal/tamarin/results/tamarin-version.txt`：

- Tamarin version：`1.12.0`
- Maude version：`3.1`
- Git revision：`82780bbaf3328a45f624ddb41e51bf75425f851c`

证明输出见 `formal/tamarin/results/tamarin-proof.txt`。本次运行报告：

```text
All wellformedness checks were successful.
protocol_executable (exists-trace): verified (6 steps)
session_key_secrecy (all-traces): verified (8 steps)
responder_agreement (all-traces): verified (8 steps)
initiator_agreement (all-traces): verified (6 steps)
initiator_injective_agreement (all-traces): verified (16 steps)
responder_counter_replay_rejected (all-traces): verified (2 steps)
cookie_gate_before_static_kem (all-traces): verified (4 steps)
response_confirm_binds_next_ratchet (all-traces): verified (2 steps)
```

如果后续修改模型后出现未证明项，优先检查：

- 是否因模型过抽象导致攻击者可伪造 response confirm。
- 是否因 trace restriction 不足导致同一 counter 被多次接受。
- 是否因 Cookie validation 与 static KEM decap 未拆分为两个规则，导致无法证明严格时序。
- 是否需要为认证 lemma 增加辅助 lemma 或 source lemma。

## 6. Sanity Check

建议做一次破坏性模型检查，但不要提交破坏版模型：

1. 临时复制 `hybrid_wireguard_v23.spthy` 为 `hybrid_wireguard_v23_no_cookie_gate.spthy`。
2. 在复制文件中合并或绕过 `Responder_Validate_Cookie_And_Mac`，让 `Responder_StaticKem_And_Response` 可直接从网络输入进入 `StaticKemDecap`。
3. 运行：

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace tamarin:init `
  tamarin-prover --prove formal/tamarin/hybrid_wireguard_v23_no_cookie_gate.spthy
```

预期结果：`cookie_gate_before_static_kem` 不再成立，Tamarin 给出攻击轨迹。这用于验证 DoS gate lemma 不是空洞成立。

## 7. 限制与假设

- 这是符号模型证明，不是计算安全证明。
- KEM、DH、AEAD、MAC、hash/KDF 均被抽象为理想原语。
- `UniqueCounterAcceptance` restriction 表达实现中的 replay cache 约束；它不是由网络消息本身自动推出的性质。
- 模型聚焦 V2.3 的安全关键路径和已验证消息状态机，没有逐字段建模 Rust 中全部消息长度、endianness、OQS 解析失败、错误传播和内存清零行为。
- 模型没有证明任意攻击者构造的畸形二进制报文都会被 Rust parser 安全拒绝；这类性质应由 fuzz/单元测试覆盖。
- DoS gate 结论只覆盖真实 UDP 来源路径；测试路径 `src=None` 不在该结论范围内。
