# 本地数据访问策略执行与脱敏审计网关

一个完全在本地运行、无外部服务依赖的 Go 参考实现：用内存数据集模拟受保护数据，
根据**主体属性 × 资源敏感级别 × 访问目的**做访问判定，对允许的字段做**字段级
脱敏 / 可逆令牌化**，并为每次访问留下带**策略版本与判定依据**的不可变审计记录。

- 结论只有三种：`allow`（原样返回）、`mask`（脱敏后返回）、`deny`（拒绝，
  且带稳定、可区分的机器可读原因）。
- 全部时间点由请求输入显式给出，默认种子固定，因此同一输入的结论与令牌可精确复现。
- 仅依赖 Go 标准库（HKDF-SHA256 按 RFC 5869 在 `masking` 包内用标准库实现）。

## 目录结构

```
internal/model    共享领域类型（主体/资源/策略/规则/判定/审计）
internal/policy   不可变版本化策略存储与生效窗口解析
internal/pdp      策略判定点：规则匹配、拒绝原因、固定版本复现
internal/masking  字段级 redact/mask 与域内可逆、跨域隔离的令牌化
internal/dataset  内存受保护数据与主体目录（实时读取，撤销立即生效）
internal/audit    追加写、读副本的不可变审计日志
internal/gateway  执行面编排：取主体/数据 → 判定 → 脱敏 → 审计
cmd/demo          本地可运行的端到端演示
```

## 策略模型

策略是**不可变（immutable）、带版本号（如 v1/v2）**的对象，含：

- `EffectiveFrom` / `EffectiveUntil`：生效窗口。窗口结束的版本不会被删除，
  而是“退役（retired）”并永久保留，供历史复现；
- 一组**有序规则**，按顺序评估，**首条完全匹配即裁决**；
- 每条规则的匹配维度：
  - 主体：角色 `Roles`、部门 `Departments`（空表示任意；命中任一即可）；
  - 资源：敏感级别 `Sensitivities`（public/internal/confidential/restricted）；
  - 目的：`Purposes` 白名单；
- 规则动作：显式拒绝（`Allow=false`）、允许（`allow`）、
  允许但必须脱敏（`RequireMask=true` + 命名的 `MaskingProfile`）。

判定前置检查（先于规则匹配）：

1. 主体 `Revoked=true` → `deny / subject_revoked`（每次请求实时读取主体状态，
   撤销对**下一次请求立即生效**）；
2. 请求时间已超过资源 `RetentionUntil` → `deny / retention_expired`；
3. 解析策略版本：
   - 固定了 `PolicyVersion` 但版本未知，或该版本在请求时间已退役
     → `deny / policy_version_expired`；
   - 未固定版本时，按请求时间取生效中的版本；没有任何生效版本
     → `deny / policy_version_expired`；
4. 规则匹配：
   - 完全命中允许/脱敏规则 → `allow` / `mask`；
   - 命中显式拒绝规则 → `deny / no_authorization`；
   - 主体/资源属性匹配但目的不匹配 → `deny / purpose_mismatch`
     （与“根本没有任何规则授权”明确区分）；
   - 其余情况 → `deny / no_authorization`。

稳定可区分的拒绝原因枚举：

| DenyReason               | 含义                                   |
|--------------------------|----------------------------------------|
| `subject_revoked`        | 主体授权已被撤销（实时）               |
| `retention_expired`      | 数据超出保留期                         |
| `policy_version_expired` | 策略版本未知/已退役/当时无生效版本     |
| `purpose_mismatch`       | 属性匹配但访问目的不在允许范围内       |
| `no_authorization`       | 无任何规则授权（含被显式拒绝规则命中） |
| `invalid_masking_config` | 脱敏配置缺失/非法                      |
| `resource_not_found`     | 资源不存在                             |
| `internal_error`         | 内部错误的统一对外原因（细节只进依据） |

> 内部错误（如数据自相矛盾、脱敏执行异常）**永远不会把原始错误透传给调用方**，
> 统一映射为 `internal_error`；具体原因只写入判定依据 `Basis` 和审计记录。

每条结论的 `Basis` 都按顺序记录：输入主体属性、资源属性与保留期、所选策略版本、
每条规则的匹配/未匹配过程、最终裁决理由，保证结论**可解释**。

## 脱敏与令牌语义

脱敏配置以命名 `MaskingProfile` 注册，逐字段配置，支持三种变换：

- `redact`：恒为 `***`，与原文无关，无法还原；
- `mask`：保留前 `KeepPrefix` / 后 `KeepSuffix` 个字符，中间替换为 `*`；
  若保留窗口会暴露全部内容，则退化为整体 `***`（宁可多遮不漏）；
- `tokenize`：**可逆**令牌化，必须指定 `TokenDomain`（令牌域）。

配置严格校验，以下情况一律返回错误（注册期或应用期），**绝不静默降级**：

- profile 名称为空、同一字段重复规则、变换类型未知；
- `tokenize` 缺少令牌域；`mask` 的保留长度为负；
- 请求要求覆盖的字段在 profile 中没有规则；
- 策略引用了未注册的 profile（网关层 → `deny / invalid_masking_config`，
  绝不返回明文）。

令牌语义与安全边界：

- 令牌 = `"tok_" + base64url(HMAC-SHA256(domainKey, value))`，
  `domainKey = HKDF-SHA256(masterSeed, "token-domain:<domain>")`；
- **同域内稳定可复现**：相同 `(域, 原值, 种子)` 永远得到相同令牌，
  因此确定性映射、可重放、可做联接分析；
- **跨域不可互相还原**：不同域的密钥经 HKDF 分离，同一原值在不同域得到不同
  令牌；用 A 域的令牌去 B 域反查必然失败（`token unknown in domain`）；
- 令牌表按域隔离存储，`Detokenize` 只能在铸造该令牌的域内成功；
- `redact`/`mask` 的输出不含足以还原原文的信息；审计里只记录令牌与“被变换字段
  列表”，**原始值永远不出现在审计内容或任何拒绝结果中**；
- 默认 `masterSeed` 是代码内固定的非秘密开发种子（保证本地可复现）；
  需要时可用 `masking.NewRegistryWithSeed(seed)` 注入自己的种子——
  不同种子产生的令牌互不相同且无法在彼此的令牌表中反查。

## 审计与保留规则

每次访问（含拒绝）都会向追加写审计日志写入一条 `Entry`：

- 审计 ID（全局唯一、单调）、时间、主体 ID/角色（快照）、资源 ID、目的；
- 命中的策略版本、命中规则、脱敏 profile、**完整判定依据 Basis**；
- 被变换字段列表；tokenize 产出的**令牌**（不存原值）。

审计条目写入时与读出时都做深拷贝，落盘后不可被外部修改；并发下 ID 唯一。

历史复现：`Gateway.Replay(auditID)` 用审计记录中固化的输入（时间、目的、
主体属性）与**当时命中的策略版本**重新判定。即使后续发布了新策略版本，
v1 下的历史结论仍按 v1 复现；复现回答的是“当时策略怎么说”，因此不套用
当前的实时撤销位（撤销是实时主体状态，不属于策略历史）。

保留期规则：

- 资源 `RetentionUntil` 之后的**新访问**被明确拒绝为 `retention_expired`，
  与普通授权拒绝可区分；
- 策略版本过了 `EffectiveUntil` 只是“退役”，不能再用于新访问
  （`policy_version_expired`），但仍保留用于历史复现；
- 零值 `RetentionUntil` 表示数据不过期。

## 并发隔离

- 所有共享组件（策略存储、数据提供方、令牌表、审计日志）均用读写互斥保护，
  判定引擎本身无状态；
- 数据读取一律返回防御性副本，请求之间不共享可变 map/slice；
- 并发测试（64 goroutine × 40 次访问 + 并发撤销）在 `-race` 下稳定通过，
  同一输入结论与脱敏结果逐字节一致，撤销另一个主体不会污染其他请求。

## 本地验证

无需任何外部服务、网络或凭据：

```bash
# 编译
go build ./...

# 运行全部测试（带数据竞争检测），日志会打印输入属性、命中策略与判定依据
go test ./... -race -count=1 -v

# 端到端演示（allow / mask / tokenize / 各种可区分拒绝 / 撤销 / 历史复现）
go run ./cmd/demo
```

演示覆盖：v1 时代分析师访问得到掩码数据、错误目的被 `purpose_mismatch` 拒绝；
v2 生效后同一目的集合收紧、字段改为令牌化；超保留期数据 `retention_expired`；
撤销主体后立即 `subject_revoked`；以及用旧审计 ID 复现 v1 下的原始结论。
