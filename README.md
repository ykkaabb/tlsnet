# TlsNet

TlsNet 是一个以云服务器为中心的 L3 虚拟网络项目，目标是在不依赖第三方
组网平台的前提下，为 Linux、Windows 和 Android 提供服务器中继组网以及
点对网访问。

公网传输使用带可配置 SNI 的标准 TLS/TCP，并行建立多条独立数据通道，降低
单条 TCP 发生重传时的队头阻塞。家庭 Linux/fnOS 节点可以发布局域网子网，
远程客户端通过云端中继访问该子网。

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

项目目前处于架构和协议重构阶段。`prototype/tlstun` 保存已经验证过的
TlsTun 0.5 多通道 Linux 点对点实现，作为新协议的数据面基线。它还不是
可替代 EasyTier 的完整组网版本。

计划中的首个完整版本包含：

- Linux 云端中继与路由服务；
- Linux/fnOS 点对网网关；
- Linux 与 Windows 访问客户端；
- 基于 Android `VpnService` 的无 Root 客户端；
- 服务端分配虚拟 IP、路由下发、子网发布授权和源地址校验；
- Wi-Fi 四通道、移动网络双通道及自动重连；
- 不提交密码、证书私钥和运行时配置。

详细设计见 [docs/architecture.md](docs/architecture.md)。

## 验证原型

需要 Go 1.24 或更高版本：

```bash
go test ./prototype/tlstun
```

Linux 构建：

```bash
go build -o bin/tlstun-prototype ./prototype/tlstun
```

## 安全提示

仓库中的代码尚未经过独立安全审计。不要把真实网络密码、证书私钥、服务器
地址或生产配置提交到 Git。子网发布权必须由服务端静态授权，不能信任客户端
自行声明。
