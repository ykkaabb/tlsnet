# TlsNet

TlsNet 是一个以云服务器为中心的 L3 虚拟网络项目，目标是在不依赖第三方
组网平台的前提下，为 Linux、Windows 和 Android 提供服务器中继组网以及
点对网访问。

公网传输支持 QUIC/HTTP3 和带可配置 SNI 的多通道 TLS/TCP。家庭 Linux/fnOS
节点可以发布局域网子网，远程客户端通过云端中继访问该子网。

## 目标拓扑

```text
Windows / Linux / Android
          │ multi-lane TLS
          ▼
Cloud relay/router (10.91.0.1)
          │ multi-lane TLS
          ▼
Home Linux gateway (10.91.0.2)
          │ optional source NAT
          ▼
Home LAN (for example 192.168.3.0/24)
```

## 已实现

- Linux 云端中继与路由服务；
- Linux/fnOS 点对网网关；
- Linux 与基于官方 Wintun 的 Windows 访问客户端；
- 基于 Android `VpnService` 的无 Root 客户端及断线重连；
- 服务端分配虚拟 IP、路由下发、子网发布授权和源地址校验；
- 真实 HTTP/3 Datagram 数据面，或 1–16 条 TLS/TCP 通道；
- QUIC 优先、TLS 自动回退、指数退避重连、坏通道剔除和有界乱序恢复；
- 密码派生认证、短时 admission token、轮换证书和固定目标回落；
- 每节点速率、包数、丢弃数、错误数和累计流量日志；
- Linux systemd、Windows 开机任务、Android APK 和 GitHub Release 打包。

详细设计见 [docs/architecture.md](docs/architecture.md)。

## 快速部署

无需预先下载任何文件。云服务器直接执行：

```bash
curl -fsSL https://github.com/ykkaabb/tlsnet/releases/latest/download/tlsnet-bootstrap.sh \
  | sudo bash -s -- relay
```

没有 curl 时使用 wget：

```bash
wget -qO- https://github.com/ykkaabb/tlsnet/releases/latest/download/tlsnet-bootstrap.sh \
  | sudo bash -s -- relay
```

引导脚本会自动识别 AMD64/ARM64、查询最新版本、下载对应 Linux 包、校验
`SHA256SUMS`，然后进入配置向导。仓库和下载均为公开访问，不需要 GitHub 账号。

云服务器完成后，在家中 Linux/fnOS 执行同一命令，只把最后的角色改为
`gateway`：

```bash
curl -fsSL https://github.com/ykkaabb/tlsnet/releases/latest/download/tlsnet-bootstrap.sh \
  | sudo bash -s -- gateway
```

Linux 访问客户端使用 `client`。服务器生成的 join code 不含密码，家庭网关和
客户端粘贴 join code 后再分别输入相同密码。

Windows 客户端直接从 Release 下载 `tlsnet-*-windows-amd64.exe` 并双击运行。
图形界面中填写 join code、节点名和密码即可。首次连接会请求一次 UAC，用于
安装内置的 Wintun 驱动和 TlsNet 后台服务；之后打开界面、连接、断开、修改配置
和查看日志均不需要管理员权限，也不再执行 PowerShell 安装脚本。界面还提供
停止服务、禁用/启用开机自启和彻底卸载；这些系统级操作会先在程序内确认，再
请求管理员权限。

### 本地构建与离线安装

需要 Go 1.26 或更高版本：

```bash
go test ./...
```

Linux 构建：

```bash
CGO_ENABLED=0 go build -trimpath -o tlsnet ./cmd/tlsnet
```

推荐在云服务器解压发布包后直接运行：

```bash
sudo ./scripts/setup-linux.sh relay
```

向导会询问公网地址、端口、家庭子网和密码，然后自动生成配置、
校验、安装并启动。结束时会打印以 `TLSNET1:` 开头的 join code；它包含服务器、
网段和 SNI，但**不包含密码**。

家中 Linux/fnOS 运行 `sudo ./scripts/setup-linux.sh gateway`，粘贴 join code、
确认自动识别的 LAN 网卡并输入相同密码。Linux 访问端运行
`sudo ./scripts/setup-linux.sh client`。Windows 使用 Release 中的原生图形程序，
粘贴 join code 并输入密码。Android 点击
**Import join code**，只填写 join code、节点名和密码。整个流程不需要手写 TOML。
云防火墙仍需同时放行向导所选端口的 TCP 和 UDP。

如需手工配置，可以复制 `configs` 中对应角色的模板，并运行
`tlsnet check -c config.toml` 后交给 `install-linux.sh`。安装后的配置位于
`/etc/tlsnet/config.toml`。卸载时运行 `sudo ./scripts/uninstall-linux.sh`；
加 `--purge` 才会删除配置。

Windows 图形程序、后台服务和 Wintun 的说明见
[`clients/windows/README.md`](clients/windows/README.md)，Android APK 的构建与使用见
[`clients/android/README.md`](clients/android/README.md)。每次 CI 都生成可安装的
Android debug APK；版本标签会同时生成 Linux、Windows 和 Android 发布包。

## 传输选择

`transport.mode = "quic"` 仅使用真实 HTTP/3 Datagrams，
`"tls-multipath"` 仅使用多 TLS/TCP，`"auto"` 优先 QUIC 并在建连失败时
回退到多 TLS。中继可以在同一数字端口上同时监听 TCP 和 UDP。

`reality.server_name` 不要求以任何固定文字开头。它决定 TLS SNI、密钥派生上下文
和未授权连接的固定回落目标；三端必须完全一致。TlsNet 的设计借鉴 REALITY 的
“认证流量进入隧道、其他流量回落”的思路，但不与 Xray REALITY 或 Hysteria 线缆
兼容，也不会冒用目标站点的私钥。

## 运行检查

```bash
systemctl status tlsnet --no-pager -l
journalctl -u tlsnet -n 100 --no-pager
ip address show tlsnet0
ping 10.91.0.1
iperf3 -c 192.168.3.200 -P 4 -t 30
```

日志中的 `traffic stats` 分别显示窗口内 `tx_mbps`、`rx_mbps`、包数、协议丢弃、
传输错误和累计字节。可用 `logging.stats_interval` 调整采样周期。

## 安全提示

代码尚未经过独立安全审计。不要把真实密码或运行时配置提交到 Git，也不要把
固定回落功能用于未获授权的第三方系统。子网发布权必须由中继的
`relay.allowed_routes` 静态授权，不能只信任客户端声明。
