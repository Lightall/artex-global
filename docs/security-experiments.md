# 身份—对象隔离实验（第一版）

本功能将操作者确认的安全预期变成可重复执行的只读 HTTP JSON 实验。工程验收使用本机固定靶标和 PostgreSQL，不调用模型。通过工程验收不代表已经证明实战漏洞召回提高。

## 当前能力与边界

- 操作者通过已登录的任务 API 配置两个不同身份、唯一目标 origin、资源及业务规则来源。正常 Agent 工具不提供配置或修改安全预期的接口；本功能不改变原平台 Bash、宿主或数据库管理权限的信任边界。
- 凭据通过服务进程环境变量引用；变量值是完整的 Authorization 或 Cookie 头，例如 `Bearer ...`。凭据值不写入配置或返回给 Agent。
- 操作者须先准备一个归属已知的资源，并给出其私有标记或 canary 的 SHA256。普通页面标题或公共字段不能充当泄露证明。
- 执行器以 GET 核验双方 principal/tenant、所有者正常访问、资源 ID、所有权和私有标记，随后用另一身份读取同一资源并再次核验该身份。整个序列重复两轮，最多 10 个请求，总时限 30 秒、单请求时限 3 秒。
- 不使用环境代理、不共享 Cookie jar、不重试、不跟随重定向，保留默认 TLS 校验。目标 origin 和路径来自操作者配置，执行工具不能覆盖它们。
- 操作者必须保证这些 GET 接口是只读操作，并符合该任务的操作约束；本功能不会把其他操作授权扩大为网络测试授权。
- 响应体上限 64 KiB。证据中的 `body_base64` 可还原存储的响应体；`sha256` 绑定已接收的原始字节，`stored_sha256` 绑定存储字节。发生凭据回显脱敏时，两者可能不同。截断时不保存正文，原始哈希仅对应已读前缀，不代表完整响应；截断不能形成合格证明。
- `violation_observed` 表示两轮中经过核验的另一身份都收到了配置所指的私有标记。它依赖操作者对私有性和业务规则的确认，不代表模型自行发现或证明了这些规则。
- 请求 URL（包括解码后的路径和查询）或测试身份凭据中已经包含的标记不能充当私有数据泄露证据；脱敏后无法从持久化响应重新证明的结果降为 `inconclusive`，不对外发布为有效阳性。
- `not_reproduced` 只表示本次指定身份、对象和业务状态下，两轮均返回 403/404 且未观察到私有标记；正文须为空或可解析 JSON。不透明、非 JSON 的异常响应保留无法确认。该结果不表示整个接口或应用安全。
- `precondition_failed` 和 `inconclusive` 都不证明安全，也不能完成“发现隔离缺陷”的目标。未结算的 `running` 记录保留未知；恢复不会自动重放请求。

## 配置与执行

本分支同时保留已有的 `/api/tasks/{id}/verification` 本地 HTTP reproduction MVP。它与本文的 `/security-experiments` 使用独立的配置及证据编号；同一任务不能同时配置两套模式，两个 operator 配置入口会在事务中拒绝混配，保留原要求。需要使用另一模式时新建独立任务，不能用另一种编号替代当前任务证据。

本文模式在普通 finding 元数据中使用 `verification_status=experiment_verified`，其 `experiment_evidence_id` 指向执行器事实节点；已有模式的 `verification_attempt_id` 指向 `test_attempts`。两者都不替代人工处置状态，旧模式的 `candidate/reproduced/legacy_unverified` 行为保留。

先通过已有任务接口取得本任务 `goal_id`。以下请求都使用已有 ARTEX 登录会话；凭据环境变量必须在 ARTEX 服务进程中设置。

`POST /api/tasks/{id}/security-experiments`

```json
{
  "goal_id": 123,
  "spec": {
    "name": "附件的身份隔离",
    "policy_source": "经确认的附件权限规则：其他租户不得读取此资源的私有标记",
    "origin": "http://127.0.0.1:9000",
    "identity_path": "/me",
    "principal_pointer": "/principal",
    "tenant_pointer": "/tenant",
    "resource_path": "/objects/owned",
    "object_id": "owned",
    "object_pointer": "/object",
    "owner_pointer": "/owner",
    "protected_pointer": "/private",
    "protected_value_sha256": "替换为操作者已知私有标记的64位小写SHA256",
    "owner": {
      "principal_id": "owner", "tenant_id": "one",
      "header": "Authorization", "credential_env": "OWNED_TEST_OWNER_AUTH"
    },
    "other": {
      "principal_id": "other", "tenant_id": "two",
      "header": "Authorization", "credential_env": "OWNED_TEST_OTHER_AUTH"
    }
  }
}
```

返回的 `id` 为 `case_id`。创建配置不会探测目标或调用模型。重新配置同一目标会创建新 case、重新打开该 goal，原配置和实验历史仍保留，旧证据不能证明新 case。

- `GET /api/tasks/{id}/security-experiments`：当前实验和各自最新结果，不执行请求。
- `POST /api/tasks/{id}/security-experiments/{case_id}/run`：显式执行，无需模型。只有配置的两个身份和 origin 会被使用。
- `GET /api/tasks/{id}/security-experiment-runs/{evidence_id}`：读取已存证据，不重放请求。

Worker 使用 `list_security_experiments`、`run_security_experiment(case_id, intent_id?)` 和 `get_security_experiment(evidence_id)`。Planner 的实际 `graph_overview` 同时包含这些实验的结果和适用范围。工具通过现有目录播种与角色绑定，数据库中被关闭的工具仍受原有装配策略控制。

`prove_goal(goal_id, evidence_id)` 对绑定了实验的目标要求当前 case 最新的已完成、重复的 `violation_observed`，并重新核对持久响应、哈希、身份和泄露判据。普通 `record_fact`、无关实验、前置失败、单纯否定以及旧版本证据都不能完成该目标。开始新实验会重新打开该 goal，旧阳性不能覆盖更新的阴性或未知结果。手动重新绑定 case 与提交目标证明在数据库事务中串行化；修改目标文字也会使原配置失效。全局 `goal_met` 不能跳过这些目标的证据约束。

### 从实验到漏洞报告

有效阳性必须先经 `report_finding(experiment_evidence_id=evidence_id, vulnclass=..., severity=..., summary=..., intent_id=...)` 登记，之后才能 `prove_goal`。`prove_goal` 可传原实验事实 ID，或已登记 finding 的探索节点 ID；两者都会解析为同一份当前实验。仅执行实验不会自动创建 finding，也不能在漏洞尚未入库时提前完成并取消 worker。

任务存在任一实验约束目标时，所有 finding 写入都要求当前有效实验。共享 `RecordFinding`、普通图节点写入及旧 standalone 写入接口均不能省略此约束；混合任务若需登记不属于该实验的其他类型漏洞，应使用独立的普通任务，不能用文字绕过本任务门禁。未绑定实验的任务保留原语义。

入库时由程序写入完整的 operator case、执行响应及哈希，并保存 `experiment_evidence_id` 和 case ID；模型填写的 `evidence` 不能替换它。同一实验重复登记返回已有 finding，不重复创建；已关闭或被判误报的 finding 不能靠重试复活。finding 的人工处置状态仍从 `pending` 开始，程序阳性不等于人工确认。

此执行器只证明配置的身份/对象隔离性质，因此实验 finding 的类别固定为 `BOLA`，名称来自 operator case，核心摘要由实际身份、对象、重复观察和范围生成，通知也使用该摘要。有效越权证据不能把模型填写的 RCE/注入等无关结论升级为已验证漏洞。严重度、业务影响和模型报告正文仍需人工审核，不能从私有标记泄露本身推断其全部危害。

现有 `report_finding` 触发器与通知入口保持连通。Reporter 使用原有 `get_task_node_detail(task_id, id=finding_node_id)` 读取完整证据、用 `update_finding_report` 写报告；普通 finding 列表保留实验引用。旧数据库保存的工具 schema 在实际装配后补充实验参数，不恢复已禁用的工具、不覆盖用户自定义描述。报告是否完成与目标达成是不同状态，工程测试不代替真实模型写报告的质量验收。

任务写入 `done` 的两个数据库入口都会重新检查当前实验及 finding，不能只信 planner 的完成标记或 goal 的 `met` 标签。证据无效、缺失、运行未结算或已被新证据替代时均拒绝；完成持久化失败时引擎不会据此取消 worker。新实验或重配会撤销已有的任务完成状态并保留暂停，不自动启动模型。规划视图中的配置失效、缺失和持久证明损坏均显式显示为未知，而非继续显示旧阳性或隐藏要求。

实际任务 Store 与 operator API 在实验开始持久化后、目标请求发出前同步运行时生命周期，避免普通 worker 路径留下旧的“完成”缓存。状态刷新失败时不发探测请求；已持久化的开始记录继续明确为未结算的未知。

## 工程验收

使用专用测试数据库，避免测试清理共享数据。零模型成本验收还应禁用 `ARTEX_REVIEW_LIVE_CONFIG`，并在宿主/容器层只允许本机测试服务出网。仅清空环境 API key 不足以阻止旧测试库中的激活配置恢复任务。整仓库回归应给每个包使用不同的测试数据库，避免跨包夹具污染。

```bash
ARTEX_PG_DSN='postgres://test_user:test_password@127.0.0.1:55432/artex_test?sslmode=disable' \
  go test ./securityexperiment ./db ./agent ./server -run 'Test.*SecurityExperiment|TestIdentityIsolation|TestRunnerRejects|TestRedirectCannot|TestTimeoutCancellation|TestCredentialRedaction|TestAudit' -count=1
```

测试覆盖本地可利用与已修复对照、身份和租户错绑、会话失效、资源/所有者错绑、无正常对照、截断、超时、状态变化、两轮不一致、重定向和凭据回显；另验证真实工具入口、实际规划工作视图、数据库重读、目标门禁、配置替换和鉴权 API 的模型调用增量为零。审查回归另覆盖删除门禁、共享写入旁路、旧 schema、请求反射、脱敏后不可复核、重复上报及人工误报处置，并从实际工具装配贯通实验、finding、Reporter 证据读取、报告写入与最终任务状态。固定调用序列不证明模型自然会选择此序列。

## 尚未覆盖

- 第一版要求操作者准备账户、业务资源和规则；尚未自动登录、创建资源或生成业务规则。
- 仅支持只读 JSON 对象中的字符串/数值及对象键 JSON pointer；不支持二进制附件、数组 pointer、修改流程、竞态、注入或跨系统流程。
- 不自动创建 finding 或替人完成漏洞处置确认。有效实验须经 `report_finding` 登记，完整执行证据由程序交接给报告入口。
- 现有未绑定实验的目标和 legacy fact/finding 保留原有行为；资产 coverage 仍表示粗略触达。不能用这些旧入口的通过状态冒称已完成新实验。
- 当前通过任务 API 和 Agent 工具使用，尚无专门前端面板。
- 对已经完成的任务重新配置或执行实验会重新打开相关 goal、撤销 `done` 并保持暂停，不自动恢复整个任务的模型执行；其他失败或超时终态不会冒称实验通过。如需继续自主探索，操作者仍须使用现有任务恢复入口。
- 尚未进行模型自然调用、保留集发现效果或线上验证；不据工程测试声称召回提升。
