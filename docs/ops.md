# 运维手册

## 服务的三个位置

| 内容 | 路径 |
|---|---|
| 代码 | `/opt/homewatch/` |
| 配置 | `/opt/homewatch/config.json` |
| 数据库 | `/var/lib/homewatch/hw.db` |
| 面板产物 | `/var/www/homewatch/` |

## 常用命令

```bash
systemctl status homewatch.timer        # 定时器是否在跑
systemctl list-timers homewatch.timer   # 下次触发时间
journalctl -u homewatch -n 20 --no-pager # 最近几次采集的输出
systemctl start homewatch.service       # 手动触发一次
python3 /opt/homewatch/hw.py status     # 命令行看状态
python3 /opt/homewatch/hw.py doctor     # 环境自检（含日志字段、异常判定线）
python3 /opt/homewatch/hw.py policy status   # 策略开关、规则、上次评估
python3 /opt/homewatch/hw.py policy limit uri_len 2048   # 改异常判定线
python3 /opt/homewatch/hw.py geo status                 # 地域封锁：开没开、生没生效、丢了多少
python3 /opt/homewatch/hw.py geo lock in --on --scope web   # 开外来封锁（只挡 Web 端口）
```

## 管理接口

```bash
systemctl status homewatch-admin        # 常驻服务（只监听 Unix socket）
journalctl -u homewatch-admin -n 30 --no-pager
curl -s --unix-socket /run/homewatch/admin.sock http://x/api/health
```

它在 `/run/homewatch/admin.sock`，权限 `0660 root:www-data`，只有 nginx 能连。
nginx 那边 `/api/` 走 basic auth，凭据在 `/etc/nginx/.htpasswd.homewatch`。

### 两个"密码"别搞混

| | 改的是什么 | 在哪改 |
|---|---|---|
| **面板登录密码** | nginx basic auth，用户名固定 `admin` | 面板「管理 → 面板登录」；`hw.py auth passwd` |
| **root 密码** | 系统账号，SSH 登录用（`/etc/shadow`） | 面板「管理 → SSH → 修改 root 密码」；`hw.py ssh passwd` |

面板上两者分成两张卡片，改面板密码不会影响 SSH，反之亦然。

改面板密码做的事：只重写 htpasswd 里 `admin:` 那一行（SHA-512 crypt，和 install 生成方式一致），
其他用户的行原样保留，文件属主和权限沿用原值（线上是 `root:www-data 0640`），
首次修改前留一份 `.htpasswd.homewatch.hw.bak`，改完 `systemctl reload nginx`。

改完**旧密码立即失效**。浏览器会继续拿旧凭据请求，所以当前页面会出现
"面板密码已更新，请重新打开页面"的黄条；关闭标签页重开后用新密码即可。
如果浏览器顽固地不再弹认证框，用无痕窗口打开一次，
或者用 `http://admin:新密码@192.168.1.50:8088/` 打开。

```bash
hw.py auth status                       # 文件位置、用户名、上次修改天数、权限告警
hw.py auth passwd                       # 交互改
printf '新密码\n' | hw.py auth passwd --stdin   # 脚本化
```

**忘记面板密码**：删掉凭据文件再跑一次 install，会重新生成并打印。

```bash
rm /etc/nginx/.htpasswd.homewatch
# 然后在本地执行
SSH_PW='...' python deploy/deploy.py install
```

**审计日志**：

```bash
tail -50 /var/log/homewatch/audit.log | python3 -m json.tool --json-lines
```

每条记录包含时间（北京时间）、来源 IP、动作、参数、结果、耗时。密码类参数写的是 `***`。

## 端口被关掉了怎么救

面板端口（8088）不允许设成「禁止入站」，所以理论上关不掉自己。
真遇到连不上，按顺序试：

```bash
# 1. SSH 进去用命令行把入站改回放行（会重建整张表）
python3 /opt/homewatch/hw.py port ctrl 8088 --dir in --mode allow

# 2. 如果 nft 规则本身出了问题，先把 input 链清空止血
#    （policy 是 accept，清空等于全放行，之后再从面板改回来）
nft flush chain inet filter input
```

如果关的是 22，就反过来：从面板管理页点「开启 SSH」，或 PVE Console 里执行同样命令。

如果规则表（`fw`）里有一条误写的拒绝规则挡在前面，端口页改「放行」是没用的——
规则表在主链上先判决。先看是谁挡的：

```bash
nft list chain inet filter fw_in     # 看规则和 comment 里的 id
python3 /opt/homewatch/hw.py fw list  # 同上，带名称
python3 /opt/homewatch/hw.py fw off <id>   # 停用这一条（保留配置）
```

## 进程守护（崩溃自动拉起）

面板「管理 → 服务」里的开关，底层是 `homewatch-admin.service` 的 drop-in：

```
/etc/systemd/system/homewatch-admin.service.d/10-homewatch-guard.conf
[Service]
Restart=always
RestartSec=3
```

```bash
python3 /opt/homewatch/hw.py svc status          # 四个单元的状态、重启次数、内存
python3 /opt/homewatch/hw.py svc guard on|off    # 开关守护（写 drop-in + daemon-reload）
python3 /opt/homewatch/hw.py svc restart homewatch-admin.service
python3 /opt/homewatch/hw.py svc heal            # 补开机自启 + 拉起没在跑的
```

重启管理接口自己时，动作会延后 2 秒执行（`systemd-run --on-active=2`），
先把这个请求的响应发回去，否则浏览器只会看到转圈。
`nginx.service` 是只读的：它挂了整站连带面板一起挂，不该在面板里点着玩。

面板显示的「已开启」读的是 **systemd 的生效值**，不是只认 drop-in：

- 有 drop-in → 以 drop-in 的 `Restart=` 为准（开关写的就是这个文件）；
- 没有 drop-in → 读 `systemctl show -p Restart`，unit 文件里自带 `Restart=always` 也算开着，
  这时「配置文件」显示的是 unit 文件路径。

所以从旧版本升上来（unit 里本来就写了 `Restart=always`）不会出现「明明在守护却显示关闭」。

## 自动封禁怎么运维

策略评估跟着每分钟的采集一起跑，不需要额外服务。常用操作：

```bash
python3 /opt/homewatch/hw.py policy status    # 开关、规则、上次结果、最近封禁
python3 /opt/homewatch/hw.py policy run       # 现在评估一次（只演练，不下发）
python3 /opt/homewatch/hw.py policy dry on    # 全局切成演练，观察一段时间误报
python3 /opt/homewatch/hw.py policy auto off  # 只识别不封禁
python3 /opt/homewatch/hw.py policy enable/disable   # 总开关
python3 /opt/homewatch/hw.py policy whitelist add 1.2.3.4
```

**误封了一个 IP**（比如合作方、爬虫）：

```bash
python3 /opt/homewatch/hw.py unblock 1.2.3.4
python3 /opt/homewatch/hw.py policy whitelist add 1.2.3.4   # 防止下一轮又封
```

只解封不加白名单的话，下一分钟评估很可能又把它封上。

**怀疑规则误判**，先看它为什么被选中：

```bash
python3 /opt/homewatch/hw.py policy status | head -30
# 面板「策略」页 → 演练一次，会列出命中规则、次数、时长
```

**紧急情况下要求立刻停止一切自动处置**：

```bash
python3 /opt/homewatch/hw.py policy disable
```

这条只停策略，不影响采集、面板和手动封禁。

内置规则升级后会**自动补进** `config.json`（只补整条缺失的，已存在的规则不动，
包括被你停用的那些）。所以要"关掉"某条规则请用面板或配置文件把它设成
`"enabled": false`，直接删掉的话下次加载会被重新加回来。

### 报文类规则和日志格式

| 规则 | 需要的日志字段 | 没配会怎样 |
|---|---|---|
| 超长 URL | 无（读请求行） | 正常命中 |
| 超大请求被拒（413/414/431） | 无（读状态码） | 正常命中 |
| 超大请求报文 | `$request_length` | 永远不命中，面板给黄色提示 |
| 恶意 User-Agent | `$http_user_agent`（combined 自带） | 不命中 |

要给 `big_req` 补上 `$request_length`，在 nginx 的 `http` 块里加一个格式并让
站点用它。**不要改默认的 `combined`**，其他工具可能依赖它：

```nginx
# /etc/nginx/nginx.conf 的 http 块
log_format homewatch '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                     '$request_length $request_time';

access_log /var/log/nginx/access.log homewatch;
```

如果各个 `server` 块自己写了 `access_log`，需要在那些行末尾补上格式名，
或者直接写 `access_log /var/log/nginx/access.log homewatch;`。
改完 `nginx -t && systemctl reload nginx`，下一轮采集会自己发现新字段
（`meta.log_has_rlen = 1`），面板上的黄色提示随之消失。

采集器对格式是**向后兼容**的：尾部有没有 `referer/UA`、有没有
`$request_length` 都能解析，缺字段只是对应规则不生效，不会报错。

### 落库的四张新表

| 表 | 内容 | 保留 |
|---|---|---|
| `geo` | IP → 国家/城市/运营商/ASN，避免重复请求在线接口 | 不清理，单行很小 |
| `bans` | 封禁流水（自动 / 手动），用于复发升级和面板展示 | 跟随 `retention_days` |
| `anomaly` | `(分钟, IP, 类型) → 次数 + 最大值`，异常请求的聚合 | 跟随 `retention_days` |
| `agent` | `(分钟, IP) → 最后一条 UA`，用于展示和识别可信爬虫 | 跟随 `retention_days` |

`bans` 只记录**真正下发**的封禁；演练和"只识别不封"都不落库，
否则一分钟一条会把记录刷满。

`anomaly` 是**采集时**判定的，判定线改动只影响之后的日志，不回填历史。
想看某条线定得合不合适，把 `policy.limits` 调小跑两天，再对着
`select kind, sum(n) from anomaly group by kind` 看数量。

## 切换封禁响应方式

三种模式，看场景选：

| 模式 | 返回 | 日志 | 什么时候用 |
|---|---|---|---|
| `visible` | `402` | 写 | 想留着"被拦了多少次"的完整证据 |
| `silent` | `444`（不回包直接断） | 写 | 默认；扫描器只能看到超时 |
| `silent_nolog` | `444` | 不写 | 被打得很凶，日志一天涨几十 MB |

```bash
python3 /opt/homewatch/hw.py policy mode            # 看当前模式 + 接线状态
python3 /opt/homewatch/hw.py policy mode silent     # 444
python3 /opt/homewatch/hw.py policy mode silent_nolog
python3 /opt/homewatch/hw.py policy mode visible    # 退回 402
```

### 它会改什么

`444` 和"不写日志"都没法只在 `conf.d/00-blocklist.conf` 里做到 —— `map` 只能
产出变量，真正回包的是站点里的 `return`。所以切模式时会对
`paths.nginx_sites`（默认 `/etc/nginx/sites-enabled`）做一次**受控改写**：

```nginx
# 改之前
access_log /var/log/nginx/home.log combined;
if ($blocked_scanner) { return 402; }

# 改之后
access_log /var/log/nginx/home.log combined if=$blocked_loggable;
if ($blocked_scanner) { return 444; }
```

改写规则：

- 只处理**含 `$blocked_scanner` 的 server 块**，别的 server、别的指令一个字不碰；
- `access_log off;` 跳过；已经挂了别的 `if=` 条件的跳过并提示（不叠两个条件）；
- 所有文件改完统一 `nginx -t`，**任何一个不通过就把全部文件还原**，不会出现
  "改了一半"的中间态；
- 幂等：已经是目标写法就报"没有改动"。

`$blocked_loggable` 的取值写在 `00-blocklist.conf` 的第二个 map 里：

```nginx
map $blocked_scanner $blocked_loggable {
    default 1;   # 正常记
    1       0;   # 只在"不写日志"时出现这行
}
```

所以以后在 `visible`/`silent`/`silent_nolog` 之间来回切，只是重写这个 map，
**不会再碰站点配置**。

### 另一种接线：include 回包片段

很多站点不是把 `return` 直接写在 server 里，而是：

```nginx
server {
    include /etc/nginx/snippets/blocked-msg.conf;   # 注意：在 server 级，不在 if 里
    ...
}
```

```nginx
# /etc/nginx/snippets/blocked-msg.conf
if ($blocked_scanner) {
    return 402 "…文案…";
}
```

这种形态下要改的是**这个片段**（`paths.nginx_reply`，默认
`/etc/nginx/snippets/blocked-msg.conf`），不是 30 个 server 块。切模式时整份重写它：

```nginx
# 封禁回包（由 HomeWatch 维护）
# 原文案：…（切回 visible 时原样还回去）
if ($blocked_scanner) {
    return 444;
}
```

三条硬约束（线上踩过，站点直接 520）：

1. **必须保住 `if ($blocked_scanner)` 这层判断**。片段是 include 在 server 级的，
   少了它就是"所有请求都 444"。检测不到判断时**拒绝改写**并报错，宁可不动；
2. 写完重读一遍自检（码对不对、判断还在不在），再拿站点自己的 `listen` +
   `server_name` 从本机发一个请求，返回 444 就还原；
   `nginx -t` 对这类事故是**完全无感**的，必须靠这条自检；
3. `systemctl reload` 是异步的，**验证要等 2–4 秒**再发请求，否则打到的是旧 worker，
   会得到"改了没生效"的假象。

### 接线状态在哪看

- 面板「管理 → 封禁 IP → 封禁响应」下方那行提示；
- `hw.py policy mode`（不带参数）；
- 每次策略评估的 `warnings`（会出现在「策略」页顶部）。

状态码对不上时提示长这样：`站点还在返回 402，点「应用」改成 444 才会静默断开`。
如果站点里压根没有 `$blocked_scanner` 引用，提示是
`站点配置里没找到 $blocked_scanner 引用，封禁规则目前不会生效` —— 说明封禁名单
写进去了但没人用，需要手工在 server 块里加：

```nginx
if ($blocked_scanner) { return 444; }
access_log /var/log/nginx/access.log combined if=$blocked_loggable;
```

### 改坏了怎么退

第一次改写前会在同目录留一份 `<文件名>.hw.bak`（只留最早那份，之后不再覆盖），
这是"HomeWatch 动它之前"的原始版本：

```bash
ls /etc/nginx/sites-enabled/*.hw.bak
cp /etc/nginx/sites-enabled/home.conf.hw.bak /etc/nginx/sites-enabled/home.conf
nginx -t && systemctl reload nginx
```

```bash
# 站点被改坏、nginx 起不来时，改回 visible 会重新走一遍校验
python3 /opt/homewatch/hw.py policy mode visible

# 手上没有 SSH：直接编辑 00-blocklist.conf 把 map 换成 default 0，
# systemctl reload nginx，所有封禁立即失效（站点里的 444 还在，但没人命中）
```

`apply_sites` 在 `nginx -t` 失败时已经自动还原了，所以"改坏"通常表现为
返回码和预期不一致，而不是 nginx 挂掉。

## Cloudflare 边缘拦截

### 为什么需要它

本地封禁解决的是"请求到了我怎么回"；推到边缘解决的是"请求根本别来"。

```
攻击者 ──▶ Cloudflare 边缘 ──命中 block 规则──▶ 结束（不回源）
                │
                └─ 未命中 ──▶ 源站 nginx ──▶ 本地封禁
```

对家里这条线路来说，边缘拦截省下的是**上行带宽**和**日志磁盘**：
请求在 CF 就被掐掉，`access.log` 里连一行都不会多。

### 怎么配

1. Cloudflare 后台 → 右上角头像 → My Profile → API Tokens → Create Token；
2. 权限选 **Zone → Firewall → Edit**，Zone Resources 只勾这一个域名；
3. 面板「管理 → Cloudflare 边缘」填 Token 和域名，点「保存」，再点「检测连接」。

```bash
python3 /opt/homewatch/hw.py cf status   # 配置形态 + 上次同步结果
python3 /opt/homewatch/hw.py cf test     # 校验 token（联网）
```

`.50` 上也可以直接改 `config.json`：

```json
"cloudflare": {
  "enabled": true,
  "api_token": "填你的 token",
  "account_id": "账户 ID（账户级 token 才需要）",
  "zone_name": "example.com",
  "auto_sync": true,
  "note": "HomeWatch",
  "timeout": 8
}
```

也可以完全不登服务器，在本地一次写进去（token 放在项目根目录 `.env`，已被
`.gitignore` 忽略）：

```bash
CF_TOKEN=xxx CF_ZONE=example.com CF_ACCOUNT=xxx python deploy/deploy.py cf
# 或者写进 .env 之后：python deploy/deploy.py cf
```

`account_id` 只在**账户级 token**（Cloudflare 后台「Account API Tokens」建的）下需要：
账户级 token 调 `/user/tokens/verify` 会 401，填了账户 ID 才能走
`/accounts/<id>/tokens/verify` 自检；不填也不影响封禁，只是「检测连接」会报错。

改完不用重启服务，下一轮采集就会读到。**token 会明文存在 `config.json`**，
面板保存时会把文件权限收到 `600`；如果是手工编辑，自己确认一下：

```bash
stat -c '%a %n' /opt/homewatch/config.json   # 期望 600
```

### 它只做什么

- 只用 **IP Access Rules**（`mode=block`），一条 IP 一条规则；
- 备注统一带 `HomeWatch` 前缀（`cloudflare.note`），**删除时只删带这个前缀的**，
  手工建的规则不会被动；
- 单轮最多推 20 个 IP、总预算 20 秒（`cloudflare.timeout` 是单请求超时）；
- 自动同步默认开：策略每次自动封禁都会顺手推一条，五分钟还会做一次全量对账
  （`cf_synced_at` 记在 `meta` 表）。

### CF 失败会怎样

**不影响本地封禁。** CF 的错误走独立通道：

- `policy.evaluate` 返回的 `cf` 字段带 `ok` / `added` / `failed`；
- 面板「Cloudflare 边缘」显示上次同步结果，失败的 IP 会在 `failed` 里；
- 摘要消息里缀一句 `Cloudflare 边缘规则：失败 1（...）`；
- 「复发次数」不会被 CF 的失败污染（只看本地下发是否成功）。

常见错误对照：

| 现象 | 原因 |
|---|---|
| `Token 无效（HTTP 401）` | token 打错、被删、或者不是这个账号的 |
| `Token 权限不足，需要 Zone.Firewall 的编辑权限` | 建 token 时少勾了 Firewall |
| `Token 下找不到域名 example.com` | 域名拼错，或 token 的 Zone Resources 没包含它 |
| `该接口已被 Cloudflare 下线` | IP Access Rules 在你这个账号被关了，改用 WAF 自定义规则 |
| `Cloudflare 限流，稍后再试（HTTP 429）` | 短时间请求太多，等五分钟 |

### 手工核对

```bash
python3 /opt/homewatch/hw.py cf rules
# 203.0.113.45   block   2026-11-09  HomeWatch auto

python3 /opt/homewatch/hw.py cf sync      # 全量对账
python3 /opt/homewatch/hw.py cf block 1.2.3.4
python3 /opt/homewatch/hw.py cf unblock 1.2.3.4
python3 /opt/homewatch/hw.py cf purge     # 清全站缓存（和封禁无关，偶尔用）
```

CF 后台也能看：Security → WAF → Tools → IP Access Rules。

### 一个容易踩的坑

边缘规则只在**流量确实经过 Cloudflare** 时生效。如果攻击者已经拿到了你的源站 IP
直连（比如历史 DNS 记录、证书透明度日志），CF 规则对它完全无效 —— 那部分只能靠
nftables + nginx。两套一起配才是完整的：

| 流量路径 | 谁在拦 |
|---|---|
| 经 Cloudflare 回源 | CF 边缘规则（第一道）→ nginx `deny`（第二道） |
| 直连源站 IP | nftables `blocked_ips` → nginx `deny` |
| SSH | nftables（只放行内网） |

## 防火墙结构

规则集由 HomeWatch 生成（`/etc/nftables.conf` 顶部有标记），结构是**命名集合**：

| 集合 | 类型 | 用途 |
|---|---|---|
| `lan4` / `lan6` | interval | 内网网段 |
| `cf_ips4` / `cf_ips6` | interval | Cloudflare 回源网段 |
| `blocked_ips` / `blocked_ips6` | timeout | 被封的 IP，到期自动失效 |
| `denied_ports` | interval | 被关闭的端口（v0.6 起只做兼容展示，真正丢不丢包看 `port_ctrl`） |
| `cn4` / `cn6` | interval | 国内网段（地域封锁用，元素由采集进程分批灌，见下节） |
| `geo_allow4` / `geo_allow6` | interval | 地域豁免：内网 + 我的 IP + CF 回源 + DNS + 自定义放行（已合并成不重叠网段） |
| `geo_on4` / `geo_on6` | interval | 闸门：空 = 地域规则不生效，塞进 `0.0.0.0/0` / `::/0` = 通电 |

链里的顺序是：`lo` 放行 → 封禁 IP → 每个受管端口按 `port_ctrl` 逐条生成
（「仅内网」是 `ip saddr != @lan4`，「仅 CF」是 `!= @cf_ips4`，「禁止」是整口 drop）
→ 出站规则（`oif != "lo"` 保护本机回环）。

改了出入站类型必须整表重建（规则条数会变），`rebuild()` 是
`nft -c -f` 校验 + `nft -f` 单事务下发，要么全成要么全不成。

改集合用 `nft add element` / `flush set`，**不要手工编辑 /etc/nftables.conf**，
下次任何开关操作都会把它覆盖掉。

要让改动重启后仍生效，走 `hw.py port ...` 或面板，它们会同时更新状态文件和配置文件。

### 有序规则表（`fw`）——和端口页是两层

端口页按端口给一个粗粒度的「放行 / 内网 / CF / 禁止」；`fw` 是一张**按顺序匹配、命中即生效**的规则表，
更适合表达「22 只给内网 + 我的出口 IP」「拒绝所有到 3306 的包」「整段放行 8000-8100」这类需求。

主链里的位置（`nft list chain inet filter input`）：

```
iif lo accept
ip saddr @blocked_ips drop            ← 封禁集合
jump fw_in                            ← 自定义规则表在这里
tcp dport 8088 ip saddr != @lan4 drop ← 端口页基线（按 port_ctrl 生成）
ct state established,related accept   ← 仅当默认策略 = 拒绝
counter drop                          ← 默认拒绝的兜底
```

由此得到两条使用约定：

- **放行规则可以穿透端口页的「禁止」**：nft 的 `accept` 是终态，规则表在端口基线之前判决。
  想把某个 IP 从「禁止」里捞出来，加一条放行规则比改端口类型更精准。
- **拒绝规则比端口页更细**：可以带来源、端口范围、协议。

三条子链各有分工：

| 链 | 挂在哪 | 内容 |
|---|---|---|
| `fw_in` | `input` | 入站规则（`ip saddr` / `ip6 saddr`，按地址族展开成多条） |
| `fw_out` | `output` | 出站规则（带 `oif != "lo"`，避免把自己回环掐死） |
| `fw_fwd` | `forward` | 只镜像 **入站拒绝** 规则，`container on` 时生效（Docker 端口走 forward 链） |

每条规则都带 `counter` 和 `comment "hw:<规则id>"`，面板上的「命中」就是从这两样读回来的：
`nft -j list chain inet filter fw_in` → 按 comment 聚合 packets/bytes。
**重建规则表会让计数器归零**，这是 nft 的行为，不是 bug。

几个防呆（后端拦，CLI 和面板都绕不过）：

- 入站拒绝 + 端口覆盖面板端口 + 来源为空或包含整个 `lan_cidrs` → 直接拒绝，
  提示「先把来源收窄到单个外部 IP」。只封某个外部 IP 的 8088 是允许的。
- 切「默认拒绝」前必须已有一条「放行面板端口且有来源」的规则，否则页面立刻打不开。
- `MAX_RULES = 200`，单条规则最多 16 个来源地址。

命令行等价操作（面板挂了也能改）：

```bash
hw.py fw list
hw.py fw add --name 面板白名单 --dir in --proto tcp --port 8088 --src 192.168.1.0/24
hw.py fw off <id>          # 停用但不删
hw.py fw del <id>
hw.py fw policy in drop    # 切默认拒绝（有前置检查）
hw.py fw nft               # 只看渲染结果，不落地
```

改完立即 `nft -c -f` 校验 + 单事务重建；校验不过会回滚到改之前的状态，不会把表改坏。

## 地域封锁

按「国内 / 境外」分流，**外来**和**对外**两个方向各一把开关。判定靠集合查找，
不查归属地库，每个新连接只多一次哈希。

### 规则长什么样

```bash
nft list chain inet filter input | grep hw:geo
# tcp dport { 80, 443, 8088, 8443 } ip saddr @geo_on4 ip saddr != @cn4 \
#     ip saddr != @geo_allow4 counter drop comment "hw:geo-in"
```

- `ip saddr @geo_on4` 是**闸门**：集合空着时这一条谁都不匹配，规则等于不存在；
- `!= @cn4`：来源不在国内网段；
- `!= @geo_allow4`：也不在豁免清单里；
- 三条同时成立才丢包。出站方向把 `saddr` 换成 `daddr`，并加 `oif != "lo"`。

外来方向放在 `jump fw_in` **之后**、端口页基线 drop **之前**，所以：

- 规则表里显式 `accept` 的地址可以穿透地域拦截，当临时白名单用；
- 端口页的「仅内网 / 仅 CF」照旧生效，两者不打架。

### 作用范围

| 范围 | 挡哪些端口 | SSH |
|---|---|---|
| `web`（默认） | 80、443、面板端口、`port_ctrl` 里标成放行/CF 的端口 | **永远不挡** |
| `all` | 所有端口 | 一起挡（等于"任何形式都进不来"） |

`web` 范围的端口是算出来的，不是写死的：新增一个对公网开放的端口，下次重建规则时
就自动进集合；`22` 和当前 `ssh_port` 无论怎么配都会被剔除。

### 为什么网段要分两次下发

`nft -f` 是**一次 netlink 批处理**，整份脚本超过约 64KB 内核就回
`netlink: Error: Could not process rule: Message too long`（实测 72KB 能过、
104KB 就挂）。6000 多个网段光元素就 100KB 出头，所以：

1. `/etc/nftables.conf` 里只声明**空的** `cn4` / `cn6` 和两个闸门集合（全文约 5KB）；
2. 建表完成后 `geoblock.fill()` 分批 `add element`，每批 900 段（单条约 17KB，
   全部 13 条跑完约 0.2 秒）；
3. 最后往 `geo_on4` / `geo_on6` 塞 `0.0.0.0/0`、`::/0`，规则一次性通电。

这样做的好处是**失败模式是安全的**：

- 灌到一半失败 → 闸门还没通电 → 地域拦截不生效，正常流量不受影响；
- 开机后 nftables 读到的是闸门空着的配置 → 同样不生效；
  第一次采集时 `geoblock.ensure()` 发现闸门空着会自动补一遍（`hw.py collect` 里做）。

想确认到底生效没有：

```bash
hw.py geo status          # 「规则生效：已通电」才是真在拦
nft list set inet filter geo_on4    # elements = { 0.0.0.0/0 } 表示已通电
nft list set inet filter cn4 | head -3   # 看网段在不在
```

### 开了之后会不会把自己挡在外面

三道保护：

1. 豁免清单自动包含 `firewall.lan_cidrs`、`own_ips`、Cloudflare 回源网段、
   `/etc/resolv.conf` 里的 DNS，以及 `geo allow` 加进去的地址；
2. `web` 范围**不含 SSH**，最坏情况下 SSH 照旧；
3. 从面板开启外来封锁时，如果请求来源（`X-Forwarded-For` / 真实 IP）本身就是境外
   且不在豁免里，后端直接报错，不写状态。

真的锁死了（比如选了 `all` 又把自己的出口 IP 从豁免里删了）：走 PVE Console / 带外，
或者内网 SSH：

```bash
hw.py geo unlock              # 关外来
hw.py geo unlock out          # 关对外
# 极端情况：直接把地域规则从表里摘掉（不重建整表，最快）
nft flush chain inet filter input   # 慎用：整条 input 链清空，policy 是 accept，等于全放行
```

### 对外封锁的影响面

开启后本机**主动发起**到境外的连接会被丢弃（已建立的连接放行，DNS 自动豁免）：

| 会失败 | 备注 |
|---|---|
| `apt update` / `pip install` | 换国内镜像源即可 |
| Let's Encrypt 证书续期 | 需把 acme 的校验地址加进 `geo allow`，或改用 DNS-01 |
| `ntp` 时钟同步 | 换国内 NTP 源 |
| Cloudflare API（边缘规则同步） | API 在境外，`cf sync` 会失败；建议只开外来不开对外 |

### 网段清单

```bash
hw.py geo cn-refresh      # 手动重拉
hw.py geo cn-list         # 打印全部网段
```

- 主源 `ispip.clang.cn`（纯 CIDR，IPv4 4339 段 / IPv6 1688 段），
  `cn.ipdeny.com` 备，官方 APNIC 委派文件留作兜底；
- 落盘在 `<db 目录>/geo_cn.json`，不进 `state.json`（几千条 CIDR 会让每次读状态都解析 100KB）；
- 只在开着封锁时每 14 天自动续一次；网段超过 30 天没更新，面板会黄字提示。

## 数据库维护

```bash
# 看今天的数据量
sqlite3 /var/lib/homewatch/hw.db \
  "select count(*), sum(n) from hits where ts > strftime('%s','now','-1 day');"

# 清理 30 天前的明细（正常由采集器自动做，这里是强制执行）
sqlite3 /var/lib/homewatch/hw.db \
  "delete from hits where ts < strftime('%s','now','-30 day');"

# 备份（建议加进 cron，体积很小）
sqlite3 /var/lib/homewatch/hw.db ".backup /root/hw-$(date +%F).db"

# 最近的封禁流水（时间是北京时间）
sqlite3 /var/lib/homewatch/hw.db \
  "select datetime(ts,'unixepoch','+8 hours'), ip, hours, rule, mode
     from bans order by ts desc limit 20;"

# 归属地缓存命中情况
sqlite3 /var/lib/homewatch/hw.db \
  "select count(*), sum(status='ok'), sum(status='fail') from geo;"
```

## 升级与回滚

改动清单见 `CHANGELOG.md`，版本号在 `homewatch/__init__.py` 的 `__version__`。

```bash
# 升级：整包上传 + 试跑 + 重启管理接口 + 自检
cd /path/to/homewatch && python deploy/deploy.py push

# 只想确认线上跑的是哪一版
ssh root@192.168.1.50 'python3 /opt/homewatch/hw.py doctor | head -3'
```

`push` 只上传代码并重启管理接口，不动 nftables、不动 nginx、不动 unit 文件；
涉及单元文件 / nginx 站点 / 首次建表的大改动才用 `install`。
升级后如果新增了集合（例如 v0.8 的 `cn4` / `cn6`），下一次开关操作会整表重建，
或者手动 `python3 /opt/homewatch/hw.py firewall init` 触发一次重建。

## 回滚

代码层面回滚很简单，把上一版覆盖回去即可。如果是从旧单文件版本升级来的，
旧文件应该还在机器上（升级前建议先备份）：

```bash
cp /opt/homewatch/hw.py.bak /opt/homewatch/hw.py
rm -rf /opt/homewatch/homewatch
systemctl start homewatch.service
```

数据库是向后兼容的：新版本只会在 `net` 表上 `ALTER TABLE ADD COLUMN` 加列，
不会删列改列，所以降级回旧版本也能继续跑。

## 面板打不开怎么查

按这个顺序看：

```bash
ss -lntp | grep 8088                              # 1. 端口在监听吗
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.1.50:8088/   # 2. 本机通吗
ls -la /var/www/homewatch/                        # 3. 产物生成了吗
journalctl -u homewatch -n 30 --no-pager          # 4. 采集报错了吗
```

如果本机通、局域网不通，检查 nftables 里 8088 的规则：

```bash
nft list chain inet filter input | grep 8088
```

规则应该是 `tcp dport 8088 ip saddr != 192.168.1.0/24 counter drop`。
如果你的网段不是 `192.168.1.0/24`，这条规则会把自己挡在外面。

## 改了 nginx 配置

```bash
nginx -t && systemctl reload nginx
```

注意 reload 是平滑的，旧 worker 会把手上的连接处理完才退出，所以
`reload` 之后立刻看日志可能还是旧 worker 写的，等几秒再看。

## SSH 关着的时候怎么进去

走 PVE 控制台：

1. 浏览器开 `https://192.168.1.234:8006`
2. 找到容器（hostname `frps`，IP `192.168.1.50`）
3. Console 进入，用 root 登录

想临时把 SSH 打开：

```bash
systemctl enable --now ssh.socket
```

nftables 里 22 端口有内网白名单，所以即使开了，公网也进不来 —— 这是有意的第二道防线。

## 换 SSH 端口

```bash
python3 /opt/homewatch/hw.py ssh port 2222     # 改
python3 /opt/homewatch/hw.py ssh port-confirm  # 用新端口登进来后确认
python3 /opt/homewatch/hw.py ssh port-rollback # 后悔了，立刻改回去
```

面板「管理 → SSH」里也有同样的按钮，改完会出现倒计时条。

### 为什么不是改 sshd_config 就完事

Debian 12 默认开 **socket activation**：端口由 `ssh.socket` 持有，sshd 只是接
systemd 递过来的 fd，所以 `sshd_config` 里的 `Port` 在这台机器上不生效。真正
决定监听端口的是：

```ini
# /etc/systemd/system/ssh.socket.d/10-homewatch-port.conf
[Socket]
ListenStream=
ListenStream=2222
```

第一行空值用于清掉从 `/lib/systemd/system/ssh.socket` 继承来的 `ListenStream=22`，
漏了它会出现"两个端口都在监听"。

HomeWatch 一次改四处，少一处就是"服务在跑但连不上"：

1. `ssh.socket` 的 drop-in（真正生效的）
2. `sshd_config` 的 `Port`（非 socket 模式下的兜底）
3. `firewall.rules` 里那条 `allow: lan` 的端口（否则新端口被 nft 丢掉）
4. `watch_ports.ssh` 和 `managed_ports`（面板显示与端口开关）

### 自动回滚保险丝

改端口是唯一能把自己锁在门外的操作，所以改完会写一个待确认状态：

- 默认 **15 分钟**（`ssh_confirm_minutes`，可设 1–120）；
- 期间面板上有个黄条，两个按钮：「我已连上，保留」和「回滚到 22」；
- 超时没人点，**每分钟的采集循环**会发现并自动改回去，审计日志里有记录。

采集循环顺手做这件事，不再单独加一个定时器——它本来每分钟就跑一次。

### 改完连不上怎么办

按顺序试：

```bash
# 1. 端口到底有没有监听
ss -lntp | grep sshd

# 2. nft 有没有放行新端口
nft list chain inet filter input | grep <新端口>

# 3. 直接回滚（不需要 SSH，走面板或 PVE Console）
python3 /opt/homewatch/hw.py ssh port-rollback
```

如果面板也进不去，PVE Console 里手工删掉 drop-in：

```bash
rm /etc/systemd/system/ssh.socket.d/10-homewatch-port.conf
systemctl daemon-reload && systemctl restart ssh.socket
```

`sshd_config` 里可能还留着一行 `Port 2222`，没有 socket activation 时会用到它，
一并改回 `Port 22`。
