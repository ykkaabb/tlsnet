# TlsNet

TlsNet 是一个以云服务器为中心的 L3 虚拟网络项目，目标是在不依赖第三方
组网平台的前提下，为 Linux、Windows 和 Android 提供服务器中继组网以及
点对网访问。

公网传输将支持 QUIC 和带可配置 SNI 的多通道 TLS/TCP。家庭 Linux/fnOS
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

## 仓库状态

项目目前已有可运行的 Linux QUIC/HTTP3 与多 TLS 通道闭环：中继分配地址、
严格授权子网发布、最长前缀转发、源地址校验、Linux TUN、网关 NAT、
故障通道剔除和有界乱序恢复。自动重连、Windows 和 Android 尚未接入，
因此还不能替代生产中的 EasyTier。

计划中的首个完整版本包含：

- Linux 云端中继与路由服务；
- Linux/fnOS 点对网网关；
- Linux 与 Windows 访问客户端；
- 基于 Android `VpnService` 的无 Root 客户端；
- 服务端分配虚拟 IP、路由下发、子网发布授权和源地址校验；
- Wi-Fi 四通道、移动网络双通道及自动重连；
- 不提交密码、证书私钥和运行时配置。

详细设计见 [docs/architecture.md](docs/architecture.md)。

## 构建和检查配置

需要 Go 1.26 或更高版本：

```bash
go test ./...
```

Linux 构建：

```bash
go build -o bin/tlsnet ./cmd/tlsnet
./bin/tlsnet check -c configs/relay.example.toml
sudo ./bin/tlsnet run -c config.toml
```

复制 `configs` 中对应角色的示例为 `config.toml`，三端填写完全相同的
`network_name`、`password` 和 `server_name`。中继必须在
`relay.allowed_routes` 中逐节点批准网关发布的子网；网关 NAT 还要把
`gateway.lan_interface` 改成实际家庭 LAN 接口。

`transport.mode = "quic"` 仅使用真实 HTTP/3 Datagrams，
`"tls-multipath"` 仅使用多 TLS/TCP，`"auto"` 优先 QUIC 并在建连失败时
回退到多 TLS。中继可以在同一数字端口上同时监听 TCP 和 UDP。

## 安全提示

仓库中的代码尚未经过独立安全审计。不要把真实网络密码、证书私钥、服务器
地址或生产配置提交到 Git。子网发布权由中继的 `relay.allowed_routes`
静态授权，不能只信任客户端声明。
