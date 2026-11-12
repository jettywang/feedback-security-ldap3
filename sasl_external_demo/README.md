# ldap3 客户端证书 + SASL EXTERNAL 接入契约（含进程内协议替身）

本目录用真实的 ldap3 客户端栈，演示并固化“客户端证书 + SASL EXTERNAL”登录目录时
的身份契约。它不需要任何外部目录，也不监听 TCP 端口：一台**进程内 LDAP 协议替身**
通过 `socketpair` 承接 ldap3 的真实 TLS 握手与 BER 编解码，按脚本返回四类应答序列。

## 1. 必须区分的三个身份（核心契约）

| 名称 | 来源 | 含义 | 能否当作最终目录用户 |
|------|------|------|----------------------|
| 证书认证身份 `cert_subject` | TLS 层客户端证书 subject（如 `CN=svc-connector,UID=connector-7`） | 证明对端持有证书私钥，是**认证**证据 | **否**。它与目录命名是两个命名空间 |
| 请求的授权身份 `requested authzid` | EXTERNAL BindRequest 的 SASL credentials 八位组（RFC 4513 §5.2.1.2） | 客户端“想以谁的身份”操作；可为空/缺省 | 否，这只是请求，服务器可改写或拒绝 |
| 实际授予身份 `granted authzid` | 服务器 WhoAmI 扩展响应（RFC 4532，OID `1.3.6.1.4.1.4203.1.11.3`） | 绑定成功后连接**真正生效**的授权身份 | **是，且唯一可信来源** |

关键规则：

- 本地证书 subject 只用于 TLS 认证，**绝不**直接当作用户 DN。
- 空 authzid（credentials 缺省）表示“由服务器做正常委托选择”，仍然可用，
  但最终身份必须由服务器经 WhoAmI 明确返回，且必须是具体的、非匿名的 DN。
- 显式 authzid 时，WhoAmI 返回的授予身份必须与请求值逐字一致，否则**失败关闭**。
- 任何绑定失败或身份核对未通过，都不得发起用户查询（searchRequest）。

## 2. 沿协议路径的追踪点

1. **TLS 配置** — `directory_client.py` 的 `Tls(...)`：加载客户端证书/私钥，
   `CERT_REQUIRED` 同时校验服务端证书链，`valid_names` 限定主机名。
   替身服务端 `CERT_REQUIRED` 强制客户端出示证书，并记录其 subject。
2. **EXTERNAL Bind 编码** — ldap3 在 `protocol/sasl/external.py` 调用
   `send_sasl_negotiation`，把 `sasl_credentials` 原样放进
   `SaslCredentials`（context `[3]`）的可选 `credentials` 字段：
   - `sasl_credentials=None` → 整个 credentials 八位组缺省（空 authzid）；
   - 字符串（如 `dn:cn=alice,...`）→ 作为请求的 authzid 逐字发送。
   `bindRequest` 的 `name` 始终为空 DN，认证信息不在 name 里。
3. **WhoAmI 扩展** — `connection.extend.standard.who_am_i()` 发送
   ExtendedRequest（OID 见上），读取 ExtendedResponse `[11]` responseValue，
   得到服务器确认的授权身份字符串。

## 3. 四个应答序列与各自证明力

| 场景 | 客户端 authzid | 服务器 BindResponse | WhoAmI | 客户端结论 | 是否查询 |
|------|---------------|--------------------|--------|-----------|----------|
| 空 authzid 委托 | 缺省 | success(0)，服务器据证书派生服务账号 | 服务账号 DN | 通过，采用服务器身份 | 是 |
| 显式且被授权 | `dn:...alice` | success(0) | 与请求一致的 alice DN | 通过且核对一致 | 是 |
| 服务器拒绝代理 | `dn:...bob` | authorizationDenied(123) | 无 | 失败关闭 | 否 |
| 返回身份不同 | `dn:...alice` | success(0) | 服务账号 DN（≠请求） | 核对失败，拒绝采用 | 否 |

每种证据能证明什么：

- **TLS 证书 subject**：仅证明 TLS 对端持有经 CA 签发的私钥（认证），不命名目录账号。
- **BindRequest credentials**：只证明客户端请求了哪个 authzid（或缺省）；是请求而非授权。
- **BindResponse result code**：证明服务器是否接受认证/代理；123 表示不存在已授权会话。
- **WhoAmI authzid**：证明连接当前**实际**持有的授权身份，是唯一可当作目录用户的值。
- **客户端约束核对**：即使 Bind 成功，只要授予身份与请求约束不符就失败关闭，
  防止静默的身份替换。
- **服务端 search 计数**：证明被拒绝/未确认身份时线路上根本没有出现 searchRequest。

## 4. 文件说明

- `make_certs.sh` / `pki/` — 本地 CA、服务端证书、客户端证书（subject 刻意不是目录 DN）。
- `ber.py` — 替身用的最小 BER/DER TLV 编解码（不依赖 pyasn1；ldap3 侧仍用自身解码器）。
- `protocol_double.py` — 进程内 LDAP 替身：真实 TLS、EXTERNAL Bind、WhoAmI、Search 应答。
- `transport_shim.py` — 把 ldap3 的出站 socket 重定向到 socketpair，绕开 TCP 监听限制。
- `directory_client.py` — 可复用的接入库：TLS、EXTERNAL 绑定、WhoAmI、身份核对、查询门控。
- `scenarios.py` / `report.py` / `run_demo.py` — 四个场景编排、证据报告、入口。
- `test_contract.py` — 固化契约的 pytest 断言。

## 5. 运行

```bash
./make_certs.sh          # 首次会自动执行，也可手动生成证书
python3 run_demo.py      # 打印四场景线路证据
python3 -m pytest test_contract.py -q
```

全程在进程内完成，已验证真实 `connect()` 调用数为 0，无外部目录、无监听端口。

## 6. 失败处理建议

- **TLS 握手失败 / 客户端证书不被信任**：不要回退到匿名或简单绑定；报错并终止，
  因为 EXTERNAL 的认证前提（已验证证书）不成立。
- **Bind 返回 authorizationDenied(123) / invalidCredentials(49) / unwillingToPerform(53)**：
  视为无已授权会话，立即解绑并返回鉴权失败；禁止任何用户查询。
- **WhoAmI 为空或不可用**：无法确认授予身份，按未授权处理，失败关闭。
- **授予身份与请求 authzid 不一致**：即使 Bind 成功也拒绝该会话，记录安全事件。
- **空 authzid 正常委托**：允许使用，但只接受服务器返回的具体 DN；拿到后再授权业务操作。
- **通信层异常（socket/超时）**：区分“网络不可用”与“鉴权拒绝”，前者可有限重试，
  后者不得重试换身份；二者都不得在身份确认前查询目录。
