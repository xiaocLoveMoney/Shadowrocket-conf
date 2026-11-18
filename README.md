# Shadowrocket 自维护配置

白名单模式：**国内直连 + 去广告 + 其余走代理**，硬约束是**零 DNS 泄漏、零 WebRTC 泄漏**。

```
小火箭/
├── shadowrocket.conf       # 主配置，导入小火箭的就是它
└── scripts/check_conf.py   # 校验：语法 / 策略引用 / 防泄漏约束 / 远程规则可达
```

## 1. 导入小火箭

**最省事：在 iPhone 的 Safari 里打开导入页** → <https://xiaoclovemoney.github.io/Shadowrocket-conf/>

页面上有三步：一键导入配置、一键复制 GeoIP 数据库链接、自动更新与泄漏自检。GeoIP 数据库只能在 App 里手动填，配置文件和链接都设置不了，所以第 2 步是复制好链接给你粘贴。

**配置链接**（在小火箭里粘贴这个）：

```
https://raw.githubusercontent.com/xiaocLoveMoney/Shadowrocket-conf/main/shadowrocket.conf
```

**方式 A：一键导入**。用 iPhone 相机扫下面的二维码，会直接跳到小火箭安装配置：

<img src="assets/import-qr.png" width="220" alt="Shadowrocket 一键导入二维码">

二维码里的内容是下面这个链接，也可以复制到 Safari 地址栏打开：

```
shadowrocket://config/add/https://raw.githubusercontent.com/xiaocLoveMoney/Shadowrocket-conf/main/shadowrocket.conf
```

**方式 B：手动添加**。小火箭 → 配置 → 右上角 `+` → 粘贴上面的配置链接 → 下载 → 点该配置 → **使用配置**。

导入后开启自动更新：

1. 设置 → 自动更新 → 配置：打开「自动后台更新」，间隔选 1 天。
2. 系统设置 → 通用 → 后台 App 刷新：给小火箭打开。

配置里已写好 `update-url`，以后只要改仓库里的文件并 push，手机端就会自动拉取。

> 远程配置更新会**覆盖**你在 App 里做的改动。所有修改都改仓库里的文件，不要在手机上改。配置里没有节点和密钥，节点订阅留在 App 里，所以仓库公开没问题。

## 2. 必做的 App 设置（不在 conf 里）

| 位置 | 设置 | 原因 |
|---|---|---|
| 设置 → GeoLite2 数据库 → 国家 URL | `https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb` | 比内置库准，每周四更新；作者推荐优先用 without-asn 版（国家数据最准） |
| 设置 → GeoLite2 数据库 → 自动后台更新 | 打开，间隔 7 天 | 跟上游周更节奏 |
| 设置 → 延迟测试方法 | CONNECT | 官方手册推荐 |
| 首页 → 全局路由 | **配置** | 选「代理」或「直连」时分流规则不生效 |
| 设置 → 代理 → 代理类型 | 银行等 App 检测到代理时改 **None（TUN 模式）** | 只影响兼容性，不影响泄漏 |

## 3. 防泄漏是怎么做到的

| 泄漏类型 | 措施（`shadowrocket.conf`） |
|---|---|
| 国外域名被国内 DNS 解析 | 所有 IP 类规则都带 `no-resolve`（含 `GEOIP,CN,DIRECT,no-resolve`），名单外的域名**不在本地解析**，直接走 FINAL 代理、由节点远端解析。上游规则集里的 IP 规则已逐个核对，都自带 `no-resolve` |
| FINAL 落到直连 | 兜底组「漏网之鱼」**故意不含 DIRECT** |
| ISP 看到 DNS 明文 | `dns-server` 只用 DoH；`fallback-dns-server` 用 DoT，不写 `system`；`dns-direct-system = false`；`[Host]` 里不指定 `server:system` |
| 解析失败回落明文 | `dns-direct-fallback-proxy = true`：直连域名解析失败改走代理解析 |
| HTTPS/SVCB 记录绕过 Fake-IP | `allow-dns-svcb = false` |
| App 硬编码公共 DNS | `hijack-dns` 劫持 8.8.8.8 / 1.1.1.1 / 9.9.9.9 / OpenDNS 等 |
| WebRTC 暴露公网 IP | `stun-response-ip = 1.1.1.1`、`stun-response-ipv6 = ::1`，STUN 拿到的是伪造地址 |
| UDP 回落直连暴露 IP | `udp-policy-not-supported-behaviour = REJECT` |
| IPv6 绕过代理 | `ipv6 = false`，不返回 AAAA |

**按设计会在本地解析的只有命中 DIRECT 的域名**（国内站、Apple/iCloud、微软服务默认直连）。这些查询走加密的国内 DoH，返回国内 CDN 地址。这是直连本身决定的，不算泄漏。介意微软域名被国内 DNS 看到，就在首页策略组里把「微软服务」切成 PROXY。

**代价**：名单（约 11 万条，含 `.cn` 整个后缀）里没有的国内小站会走代理。连不上或很慢时，在 `[Rule]` 第 0 节加一行 `DOMAIN-SUFFIX,xxx.com,DIRECT`。

### 验证方法（连上后用 Safari 打开）

- <https://browserleaks.com/dns>、<https://ipleak.net>：DNS 服务器只能显示节点所在地，不能出现中国大陆的运营商、阿里或腾讯。
- <https://browserleaks.com/webrtc>：Public IP 不能是你的真实 IP。
- 小火箭 → 数据 → DNS 日志：访问国外网站时不应出现对应域名的本地查询。

## 4. 规则顺序与数据源

规则从上往下匹配，模块优先于配置。另外小火箭编译时会把 GEOIP 后置，FINAL 永远放在最后。

| 节 | 内容 | 数据源 | 更新频率 |
|---|---|---|---|
| 0 | 个人规则（修误杀 / 漏网） | 自己写 | 随时 |
| 1 | 局域网 / 私有域名 → DIRECT | blackmatrix7 Lan、Loyalsoldier private | 每日 |
| 2 | 去广告 → REJECT | blackmatrix7 AdvertisingLite（3.7 万条） | 每日 |
| 3 | AI / Telegram / 谷歌 / 流媒体 / GitHub / 微软 / 苹果 | blackmatrix7 各服务 `.list`，Loyalsoldier apple、icloud | 每日 |
| 4 | 国外 → PROXY，国内 → DIRECT | Loyalsoldier `proxy.txt` / `direct.txt` | 每日 06:30 |
| 5 | Telegram IP、`GEOIP,CN`（全部 no-resolve） | Loyalsoldier telegramcidr + App 里的 mmdb | 每日 / 每周 |
| 6 | FINAL → 漏网之鱼 | — | — |

**为什么说「兼容 GEO 文件」**：小火箭不支持 `geosite.dat`，只能读 mmdb 格式的 GeoIP 和 ASN。所以这里分两部分对齐 v2ray/Clash 那套 GEO 数据：

- 域名部分用 Loyalsoldier/surge-rules。它和 `geosite.dat` 一样由 v2fly/domain-list-community 加上 dnsmasq-china-list 生成：`direct.txt` 对应 `geosite:cn`，`proxy.txt` 对应 `geolocation-!cn`。
- IP 部分用 Loyalsoldier/geoip 的 mmdb。

你在电脑上的 Clash / sing-box 如果也用 Loyalsoldier 的 GEO 文件，两边分流结果基本一致。

**广告加强版**：把第 2 节换成 Loyalsoldier `reject.txt`（20 万条）。拦得更多，但更吃 iOS 网络扩展的 50 MB 内存上限，误杀也更多。同时还挂着别的大名单时，不建议换。

## 5. 日常维护

```bash
python3 scripts/check_conf.py            # 离线校验，每次改完必跑
python3 scripts/check_conf.py --online   # 额外下载全部远程规则，确认链接都活着
```

校验器会拦下这些问题：IP 规则缺 `no-resolve`、FINAL 能落到 DIRECT、DNS 里出现明文 IP 或 `system`、缺少 STUN 伪造参数、策略组引用了不存在的策略、FINAL 不在最后、远程规则 404 或为空。

调试分流用小火箭 → 配置 → 编辑配置 → **测试规则**，输入域名就能看到它命中哪条规则、走什么策略。

## 6. 借鉴来源

- [LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket)：社区使用手册，参数语义以它为准；`lazy_group.conf` 是策略组写法的样板
- [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)、[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)：GEO 同源域名集和 mmdb
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)：按服务拆分的规则集
- [GMOogway/shadowrocket-rules](https://github.com/GMOogway/shadowrocket-rules)：思路是把规则做成模块，个人覆盖规则单独建一个小模块放在最上面（模块优先级高于配置）
- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)：GFWList 加 EasyList 转换的整份 conf，适合拿来对比
