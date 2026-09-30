# wireguardJS

面向 KANO Android 设备管理页面的 WireGuard 管理插件。保留单文件接入和离线安装，源码、设备脚本和构建工具分别维护。

## 使用

1. 下载根目录的 `wireguard.js`，或者从 Releases 下载同名文件。
2. 将文件内容放入原管理页面的自定义 JS / 插件入口，与旧版接入方式一致。先移除旧版脚本，再刷新页面，避免重复加载。
3. 在原管理页面启用高级功能和 root 权限，展开 WireGuard，点击 **安装 / 升级**。
4. 读取配置，填写自己的私钥、公钥、服务器地址和隧道地址。先校验，再保存和启动。
5. 在连接状态里确认最近握手及收发流量。仅“运行中”不代表对端可达。

`wireguard.js` 已内置完整资源包，安装时不需要访问 GitHub。`dist/wireguard-resources.tar.gz` 和 `dist/manifest.json` 是独立发布产物，供审计和校验使用。

从 v2.0.0 升级时，先替换页面里的 JS 并刷新，再点击 **安装 / 升级** 更新设备资源。只替换页面 JS 不会更新设备上的校验和网络脚本。旧配置会保留，新界面会提醒资源版本不一致。

## 功能

- 安装、升级、启动、停止、重启、卸载和开机自启。
- 配置校验，支持多个 Peer、IPv4、IPv6 和双栈隧道，以及 IPv4 / IPv6 服务器 Endpoint。
- 配置导入导出、保存前自动备份、手动备份和恢复上一份配置。
- 升级保留配置及备份，验证资源包 SHA-256；升级失败尝试恢复旧版本和原运行状态。
- 日志、节点状态、设备诊断和诊断输出导出。
- 单次轮询完成后再安排下一次刷新，页面隐藏或面板折叠时暂停。
- 窄屏单列布局、未保存修改提醒、操作期间禁用重复提交。
- 配置和运行快照使用 `600` 权限，资源目录使用 `700`；脚本和可执行文件使用 `755`。
- DNS 规则放入专属链，并按运行快照清理，避免修改配置后旧规则残留；清理失败时保留快照以便重试。
- IPv6 策略路由、转发和 NAT66；启动前检测所需功能，停止或失败时清理两个地址族的规则。
- 开启 IPv6 转发前保存 RA 和转发参数，保留上游 RA 学到的默认路由，停止时恢复本插件修改的参数。

## 设备要求

- Android ARM64 / AArch64。当前 `resources/bin/wg` 来自原始脚本内置包，未重新编译。
- root 权限，内核支持 `ip link add wg0 type wireguard`。本插件不安装内核模块或 userspace WireGuard 后端。
- `sh`、`ip`、`iptables`、`awk`、`tar`、`base64`、`sha256sum` 及常见 Shell 工具；部分操作支持 toybox / busybox 回退。
- IPv6 隧道还需要内核 IPv6、IPv6 策略路由和 `ip6tables` 的 filter / mangle 表；启用 NAT 或 IPv6 DNS 时还需要 IPv6 nat 表及对应 MASQUERADE / DNAT 扩展。`NAT=false` 配合 DNS 还需要 owner 匹配扩展。纯 IPv4 配置不要求 `ip6tables`，纯 IPv6 配置不要求 `iptables`。
- 原管理页面提供 `.functions-container`、`runShellWithRoot`、`createToast`、`KANO_baseURL`、`common_headers` 和 `/upload_img` 接口。`collapseGen` 可选。
- 上传接口返回 `/data/data/com.minikano.f50_sms/files` 下的相对路径，这与原插件约定一致。

Windows / 普通浏览器不能直接控制设备。`preview.html` 只用于本地界面预览，使用模拟设备，不会执行 Shell，也不会连接真实设备。

## 配置约定

IPv4 示例见 [`resources/wg0.conf`](resources/wg0.conf)，双栈示例见 [`examples/wg0-dualstack.conf`](examples/wg0-dualstack.conf)。其中密钥、服务器和地址均须替换为自己的配置。

| 字段 | 说明 |
| --- | --- |
| `Address` | IPv4 或 IPv6 地址及前缀，例如 `10.6.0.2/32, fd00:6::2/128` |
| `AllowedIPs` | IPv4 / IPv6 CIDR；双栈全流量使用 `0.0.0.0/0, ::/0`，每个地址族均需对应的 Interface Address |
| `Endpoint` | `host:port`、`IPv4:port` 或 `[IPv6]:port`；被动接入节点可省略 |
| `DNS` | 每个地址族最多一个 DNS 地址，各自必须被同族 AllowedIPs 覆盖；省略或留空则不接管 DNS |
| `LANInterface` | LAN 网卡名，默认 `br0`，最长 15 个字符 |
| `NAT` | 默认开启，分别添加 IPv4 NAT / IPv6 NAT66；`false` 关闭 LAN 常规源 NAT，需要服务端具备到 LAN 网段的返回路由 |
| `MTU` | 纯 IPv4 最低 576；含 IPv6 地址时最低 1280、未指定则使用 1420；最大 9000，实际取值受路径限制 |

不执行 `PreUp` / `PostUp` / `PreDown` / `PostDown` 等钩子；`Table`、`SaveConfig` 等 wg-quick 专用设置也不受支持。保存时会明确拒绝这些字段。

策略作用于指定 LAN 网卡入站的 IPv4 / IPv6 流量；AllowedIPs 路由只放进对应地址族的策略表，不会改写网关自身的默认出口，也不提供断线阻断（kill switch）。IPv6 链路本地、组播和实际 LAN 前缀保留本地可达性；其余流量按配置的 AllowedIPs 转发。

DNS 配置通过独立的打标和 DNAT 链接管相应地址族的普通 TCP / UDP 53 流量，包含 LAN 和网关自身的查询。IPv4 DNS 不会重定向 IPv6 DNS，反之亦然。使用 UDP 53 作为 WireGuard Endpoint 端口时，同族 DNS 接管会与隧道传输冲突，应省略 DNS；域名 Endpoint 无法预先确定地址族，端口 53 与任何 DNS 接管配置不允许同时使用。

`NAT=false` 时，本机被重定向的 DNS 仍单独转换源地址到隧道地址，避免携带外网源地址而被远端 Peer 拒绝；此规则不对普通 LAN 转发包做源 NAT。完全不需要 NAT 时，同时省略 DNS 配置。

插件不提供 DHCPv6、路由通告（RA）或前缀委派服务。LAN 客户端需要已有 IPv6 地址和 IPv6 网关。服务端也必须将客户端的隧道 IPv6 地址加入对应 Peer 的 AllowedIPs，并提供 IPv6 出口；`NAT=false` 时还需配置到 LAN IPv6 前缀的返回路由。配置通过校验不等于服务端已经满足这些条件。

插件使用接口 `wg0`，分别在 IPv4 / IPv6 中使用策略表 `101`、规则优先级 `100`、标记 `2`。请勿让其他服务同时管理这些资源。启动前检查策略表和规则冲突；停止时只清理本插件接口的表内路由。IPv4 转发保持原有行为，启用后不关闭；IPv6 全局转发若原本关闭，会先把原为 `1` 的相关 `accept_ra` 调整为 `2`，停止时按快照恢复。原本已启用 IPv6 全局转发的设备不重复改写该参数。

## 数据和升级

- 安装目录：`/data/kano_wireguard`
- 配置：`wg0.conf`
- 上一份配置：`wg0.conf.bak`
- 活动配置快照：`.state/active.conf`，停止时用于清理实际生效的网络规则
- IPv6 系统参数快照：`.state/ipv6-sysctl`
- 上一版资源：`/data/kano_wireguard.previous`
- 开机自启文件：`/sdcard/ufi_tools_boot.sh`

保存配置不会自动重启。恢复备份会交换当前配置和上一份配置，随后需要手动重启。卸载会删除当前资源、配置、备份、上一版资源和本插件的自启项。

升级会短暂停止运行中的连接；如果安装或重新启动失败，会尝试恢复上一版。如果新版本的网络清理仍失败，会保留当前目录、运行快照和上一版资源，需先重试停止、完成清理后再安装。断电或进程被强制终止时无法保证自动回滚。异常中断可能留下 `/data/local/tmp/kano_wireguard.lock`；诊断确认没有安装、保存或启停操作正在运行后，才能由设备管理员清理该目录。

导出的配置含私钥，不要提交到仓库。日志导出会对 `PrivateKey` / `PresharedKey` 配置行做脱敏；原管理页面的上传接口及网络连接仍须由使用者信任。

## 开发

需要 Node.js 22+、Python 3.13 和 Bash。Windows 可使用 Git for Windows 提供的 Bash。

```sh
npm ci
npm run build
npm test
npm run check
npx playwright install chromium
npm run test:ui
```

Windows 上 UI 测试优先使用已安装的 Microsoft Edge；其他环境默认使用 Playwright Chromium。直接打开 `preview.html` 可查看交互预览。

```text
src/config.cjs             配置解析、校验、脱敏
src/plugin.js              管理页面 UI 与设备通信
resources/install.sh      校验、保留配置、升级和回滚
resources/scripts/        启停、配置管理、锁和设备端校验
resources/scripts/network.sh 双栈路由、防火墙、DNS 和 IPv6 系统参数
resources/bin/wg           原版 ARM64 二进制
tools/build.py             生成单文件插件、压缩包和清单
tests/                     配置、Shell 故障注入、浏览器交互测试
wireguard.js               生成的插件文件
dist/                      独立资源包与 SHA-256 清单
```

修改 `src/` 或 `resources/` 后重新构建，不要手动修改生成的 `wireguard.js`。构建过程只使用 Python 标准库，固定归档时间戳和文件权限，不包含当前机器路径、真实配置或密钥。

`tools/import_legacy.py` 仅用于最初从旧版压缩脚本导入资源。原始备份位于被 Git 忽略的 `.local/wireguard.original.js`，不要对当前构建产物再次导入。

## 测试范围

自动测试覆盖前端与设备端的双栈校验一致性、双栈路由及 DNS、IPv6 NAT、修改 DNS / 网卡后的清理、IPv6 功能缺失和失败回滚、RA / 转发参数恢复、配置备份恢复、保存失败、升级保留配置、SHA-256 失败、升级启动失败回滚、自动启动项以及桌面 / 手机布局。

Shell 测试在隔离目录中使用模拟网络命令，不改变测试主机的路由或防火墙。尚需在真实目标设备上确认 SELinux、内核 WireGuard、iptables / ip6tables 扩展、上游 RA、启动脚本调度及 IPv4 / IPv6 握手和流量转发。

## 发布

GitHub Actions 在推送和 PR 时运行构建与测试。推送 `v*` 标签后发布 `wireguard.js`、资源包和清单到 Releases。

```sh
git tag v2.1.0
git push origin v2.1.0
```

版本号取自 `package.json`。二进制来源及许可状态见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
