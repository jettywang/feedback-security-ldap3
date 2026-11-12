# ldap3 Kerberos 服务主体选择安全审查（SSO 目标名）

- 版本：ldap3 2.10.2rc4（工作区源码，可编辑安装）
- 核心代码：`ldap3/protocol/sasl/kerberos.py:118` `_common_determine_target_name`
- 枚举与反查：`ldap3/core/rdns.py`
- 复现脚本：`secreview/kerberos_target_repro.py`（假 gssapi / winkerberos + 可控 PTR 桩，无需域控/票据/网络）
- 原始证据：`secreview/matrix-before-fix.txt`（修复前）、`secreview/matrix-after-fix.txt`（修复后）

## 1. 结论速览

POSIX（gssapi）与 Windows（winkerberos）两条绑定路径都调用同一个
`_common_determine_target_name`，目标名恒为 `ldap@<hostname>`，再分别交给
`gssapi.Name(..., hostbased_service)`（kerberos.py:234）或
`winkerberos.authGSSClientInit`（kerberos.py:281）。矩阵中两后端 28 个用例
逐行一致，证明目标名选择与平台无关。

认证对象（向哪个 SPN 申请票据）的优先级：

1. `sasl_credentials` 为空 / 首元素为 `None` / `False` / `ReverseDnsSetting.OFF`：
   使用 `Server(host)` 里配置的主机名，**不做任何 DNS 反查**。
2. 首元素为字符串：直接使用该字符串，**完全不碰 DNS**（显式钉扎，最安全）。
3. 首元素为 `True` 或任一反查枚举：对**实际对端 IP**
   `socket.getpeername()[0]` 做 `gethostbyaddr`，PTR 结果成为 SPN 主机部分。
   这意味着 DNS 返回的名字被直接当作认证对象——不应天然信任。

## 2. 四种配置在“连接名 / 对端地址 / PTR 名”不一致时的行为

矩阵固定：连接名 `ldap.example.com`，对端 `10.0.0.10`，PTR 返回
`ldap-3.internal.example.com`。

| 配置 | 反查次数 | 实际 SPN | 认证对象是否被 DNS 改变 |
|---|---|---|---|
| 默认 / `False` / `OFF` | 0 | `ldap@ldap.example.com` | 否，钉在配置名 |
| 字符串覆盖 `('ldap-3.example.com',)` | 0 | `ldap@ldap-3.example.com` | 否，钉在显式名 |
| `True` / `REQUIRE_RESOLVE_ALL_ADDRESSES` | 1 | `ldap@ldap-3.internal.example.com` | **是，完全由 PTR 决定** |
| `REQUIRE_RESOLVE_IP_ADDRESSES_ONLY`（host 为主机名） | 0 | `ldap@ldap.example.com` | 否（仅当 host 是 IP 字面量才反查） |
| `OPTIONAL_RESOLVE_ALL_ADDRESSES`（PTR 有应答） | 1 | `ldap@ldap-3.internal.example.com` | **是，PTR 一应答即静默切换** |
| `OPTIONAL_RESOLVE_IP_ADDRESSES_ONLY`（host 为主机名） | 0 | `ldap@ldap.example.com` | 否 |

## 3. 失败、IPv4/IPv6、别名矩阵：改变认证对象 vs. 仅影响可用性

### 3.1 PTR 解析失败（对端 10.0.0.99 / fd00::99，无 PTR）

| 配置 | 结果 | 性质 |
|---|---|---|
| `True`、`REQUIRE_ALL`、`REQUIRE_IP_ONLY`（host 为 IP） | 抛 `gaierror`，绑定中止 | **仅可用性**：未发出任何票据，认证对象没有被改变 |
| `OPTIONAL_ALL` | 回退 `ldap@<Server.host>` | 回退改变了“本会使用的名字”，但回退目标是管理员配置名，非 DNS 数据 |
| `OPTIONAL_IP_ONLY`（host 为 IP） | 回退到 `ldap@10.0.0.99`（IP 字面量 SPN） | 同上；实际 KDC 通常无此 SPN，表现为后续可用性失败 |
| `OFF` / 默认 / 字符串 | 不反查，不受影响 | 无影响 |

要点：**REQUIRE 系列的失败是 fail-closed（连不上），OPTIONAL 系列的“成功”才是
安全敏感点**——PTR 只要有应答（无论真假），SPN 就被替换，没有任何对 PTR 名与
连接名一致性的校验。DNS 投毒/中间人控制反向区即可让客户端向攻击者控制的 SPN
申请 TGS 票据。

### 3.2 IPv4 / IPv6 字面量作为 Server.host

- `OFF`：目标为 `ldap@10.0.0.10` / `ldap@fd00::10`，不反查（KDC 一般没有
  IP 形态 SPN，通常只是可用性问题）。
- `*_IP_ADDRESSES_ONLY`：`is_ip_addr()`（rdns.py:53，AF_INET+AF_INET6
  `inet_pton`）识别后才反查；IPv4 与完整/压缩 IPv6 均验证通过。
- `REQUIRE_ALL`：无论 host 形态都反查；无 PTR 即 `gaierror`。

### 3.3 服务器别名（连接名 ldap-alias…，对端 PTR 为 alias-result…）

- `OFF` → `ldap@ldap-alias.example.com`；字符串覆盖 → 显式名；均与对端无关。
- `REQUIRE_ALL` / `OPTIONAL_ALL` → `ldap@alias-result.internal.example.com`，
  连接名被完全忽略，认证对象由 PTR 决定。

## 4. 发现的实现缺陷与最小修正（本次已修复）

### 缺陷：`ReverseDnsSetting` 成员是一元元组，不是整数

`ldap3/core/rdns.py` 原代码每个常量带尾随逗号：

```python
OFF = 0,
REQUIRE_RESOLVE_ALL_ADDRESSES = 1,
...
```

实测（修复前）：

```
ReverseDnsSetting.OFF == (0,)   # bool((0,)) is True
SUPPORTED_VALUES = {(0,), (1,), (2,), (3,), (4,)}
1 in SUPPORTED_VALUES -> False  # 文档承诺的整数值全部无法命中
```

后果（矩阵原始证据）：

- 传枚举成员本身：靠元组身份在 `SUPPORTED_VALUES` 内“碰巧”工作；
  `OFF=(0,)` 为真值，仅因选择器内没有任何分支命中而退回 server.host，
  与注释“OFF has value 0”的语义不符。
- 按公开整数语义传 `(1,)`、`(3,)` 等：落入 `elif` 集合判断为假，
  再落入字符串分支执行 `'ldap@' + 1`，抛
  `TypeError: can only concatenate str (not "int") to str`——功能不可用，
  且不是安全失败而是代码异常。
- 传 `0` 因 falsy 偶然等价 OFF；`True/False` 走独立 `is True` 分支不受影响。

修正（`ldap3/core/rdns.py`）：去掉 5 个尾随逗号，成员成为真正的 int；
`SUPPORTED_VALUES` 自动变为整数集合。修复后矩阵中 `(1,)`→
`ldap@ldap-3.internal.example.com`、`(3,)` 同构，全部 `OK`，且枚举成员
路径输出与修复前逐行一致（无行为回归）。

回归：

- `test/testRdns.py`：原测试把元组错误固化（断言 `OFF == (0,)`），已改为
  断言整数、falsy、整数字面量属于 `SUPPORTED_VALUES`。
- `test/testKerberosTargetName.py`（新增，15 用例）：用 mock 的反查桩直接
  覆盖共用选择器，包含钉扎、反查切换、PTR 失败回退、IPv4/IPv6、整数字面量。
- 离线测试：`pytest test/testKerberosTargetName.py test/testRdns.py
  test/testSaslPrep.py` → 21 passed。
- 注：`test/` 全目录收集依赖真实 LDAP（test/config.py testing location 未配置），
  与本次改动无关。

未采用“禁用服务端认证”之类的绕过；修复仅恢复参数既有公开语义，安全姿态
由部署配置（第 5 节）保证。

### 另发现（未改，超出本次范围，仅记录）

`kerberos.py:211` 用 `negotiated_token[1:] != '\x00\x00\x00'` 比较 bytes 与
str，Py3 下恒真，导致无安全层的正常结束令牌也会抛
"Server max buffer size must be 0"。这是 GSS 封装层的 Py3 兼容缺陷，
不影响目标名选择；复现脚本以内存桩绕过，未改动库代码。

## 5. 严格部署配置（可执行）

文件：`secreview/deployment/strict_kerberos_client.py`、
`secreview/deployment/krb5.conf.strict`。要点：

- 只用 `ReverseDnsSetting.OFF`（默认）或字符串显式覆盖；禁止
  REQUIRE_*/OPTIONAL_* 反查模式——DNS 名不作为信任锚。
- 多主机/轮询场景：为池内每台机器在 KDC 注册 `ldap/<real-host>@REALM`，
  客户端用字符串覆盖钉扎到具体 SPN，或使用统一 SPN（主机名随服务漂移）。
- TLS 强制 `CERT_REQUIRED`；GSS 互相认证保持开启（winkerberos 路径默认带
  `GSS_C_MUTUAL_FLAG`）。
- POSIX 侧 krb5.conf 同时设置 `rdns=false` 与
  `dns_canonicalize_hostname=false`，防止 gssapi/MIT krb5 在库外再次做
  DNS 规范化，把 ldap3 传入的名字改写。
- 自检（无需服务器）：`python strict_kerberos_client.py --self-check`，
  已验证三个不同对端（含 PTR 缺失、IPv6）下目标名恒定。
