# JarsAuth Device Approval

这是面向 Minecraft 1.20.1 Forge 小型服务器的客户端/服务端双端认证模组，基于 [Jissee/JarsAuth](https://github.com/Jissee/JarsAuth) 修改。

6.0.0 将旧版可复制的设备 UUID 升级为“设备 Ed25519 密钥 + 玩家独立恢复密钥”。认证发生在 Forge 登录协商阶段，未通过认证的连接不会进入游戏世界，因此即使客户端无法渲染或不能发送游戏内命令，也能完成登录验证。

## v6 的身份模型

- 每个玩家、每个服务器独立拥有一把恢复密钥，不能跨玩家或跨服务器使用。
- 同一操作系统账户、同一台电脑上的多个 PCL/游戏实例默认共享设备身份。
- 设备私钥不会发送给服务器；客户端只发送公钥和针对本次随机挑战的签名。
- Windows 上本地安装密钥使用当前用户的 DPAPI 保护；设备私钥和恢复私钥再使用 AES-GCM 加密保存。
- 客户端数据带有本机绑定校验。直接把整合包或 JarsAuth 数据复制到另一台电脑时，无法通过本机校验的设备凭据会被归档并重新生成。
- 首台设备自动登记。新设备可用玩家自己的恢复密钥直接登记；没有恢复密钥时进入管理员待审批队列。
- 已经迁移到 v6 的玩家不会因为撤销最后一台设备而退回“首台设备自动登记”状态。

这套机制的目标是防止整合包复制后连同登录身份一起泄露，并解决 OP 不在线时玩家换设备的问题。它不替代正版登录、白名单、网络隔离和服务器日常安全维护。

## 安装与兼容性

客户端和服务端必须安装完全相同的 jar：

```text
mods/JarsAuth-forge-1.20.1-6.0.0.jar
```

要求：Minecraft 1.20.1、Forge 47.x（当前构建基于 47.4.13）、Java 17。

v6 登录协议与 5.x 不兼容。升级时必须在维护窗口同时替换客户端和服务端 jar；不要只更新一端。

## 从 5.x 迁移

服务器会继续读取原来的 `device-files/<玩家名>.json`。玩家第一次用已批准的旧设备连接时，会在登录协商中证明旧凭据，同时生成设备密钥和玩家恢复密钥，随后原子写入 v2 数据。

迁移完成后，当前设备成为已批准设备，账户被永久标记为 v2，客户端生成恢复密钥备份。服务端数据升级前应备份整个 `device-files` 目录。

## 恢复密钥

Windows 默认共享数据目录：

```text
%LOCALAPPDATA%\JarsAuth
```

Linux 默认目录为 `$XDG_DATA_HOME/JarsAuth`，未设置时为 `~/.local/share/JarsAuth`；macOS 默认目录为 `~/Library/Application Support/JarsAuth`。

服务器首次接受玩家的恢复密钥后，客户端会在 `JarsAuth/recovery-backups/` 生成一个按服务器和玩家作用域命名的备份文件。恢复文件含有私钥，任何得到它的人都能为对应玩家登记新设备。不要把它放进公开整合包、网盘分享目录、聊天记录或截图中。

换电脑时，把完整备份文件复制到新电脑的：

```text
JarsAuth/recovery-import/
```

然后正常连接服务器。客户端会在进入世界之前使用恢复密钥签名本次挑战；服务端验证成功后批准新设备，并将导入的密钥放入本机加密存储。恢复文件带服务器和玩家作用域，放错账户不会被接受。

已登录玩家可以轮换恢复密钥：

```text
/jarsauth recovery rotate
```

轮换操作同时需要旧恢复密钥签名和新恢复密钥自签名。服务端确认后客户端才提升新密钥并写出新备份；旧备份随即失效。

## 玩家命令

```text
/jarsauth devices
/jarsauth device rename <设备ID或唯一前缀> <新名称>
/jarsauth device revoke <设备ID或唯一前缀>
/jarsauth recovery rotate
```

重命名、撤销和轮换都由玩家恢复密钥授权，服务端还会校验一次性随机数、签发时间和账户修订号，防止旧请求被重放。

撤销当前设备后，本次在线会话不会被强制踢出，但下次登录将无法再使用该设备。撤销前应确认仍持有有效恢复备份。

## 管理员命令

```text
/jarsauth pending
/jarsauth approve <requestId>
/jarsauth reject <requestId>
/jarsauth reload
/jarsauth record
```

待审批记录持久化在玩家设备文件中，服务器重启后会重新建立审批句柄。损坏的单个玩家 JSON 会被记录并跳过，不会阻止其他玩家数据加载或服务器启动。

## 配置与审批接口

世界根目录中的 `setting-client-auth.json`：

```json
{
  "enabled": true,
  "interval": 10,
  "timeout": 5,
  "approvalPort": 8787,
  "approvalBindHost": "0.0.0.0",
  "approvalPublicBaseUrl": "http://127.0.0.1:8787",
  "approvalPermissionLevel": 4,
  "approvalExpireMinutes": 30
}
```

- `enabled`：启用认证。
- `approvalPort` / `approvalBindHost`：内置审批 HTTP 服务的监听端口和地址。
- `approvalPublicBaseUrl`：管理员收到的审批链接前缀。
- `approvalPermissionLevel`：接收审批消息及执行管理命令的权限等级。
- `approvalExpireMinutes`：审批请求有效期。

内置接口只提供 HTTP，不直接管理 TLS 证书。推荐的公网结构是：

```text
浏览器 --HTTPS--> Cloudflare/反向代理 --HTTP或隧道--> JarsAuth 审批端口
```

如果只用 FRP TCP 转发，`approvalPublicBaseUrl` 应填写管理员实际访问的地址和端口。若使用 `https://`，TLS 必须在 Cloudflare、Nginx、Caddy 等上游终止；仅把 HTTP 端口通过 FRP 暴露出去不会自动变成 HTTPS。审批链接包含一次性高熵令牌，仍应限制暴露范围并避免记录完整 URL。

Minecraft 的 SRV DNS 记录可以让 `mc.kkbk.info` 指向游戏端口，但它不能代理这个 HTTP 管理接口；游戏入口和管理入口应使用不同的记录或子域名。

## 密码学与性能

- Ed25519：设备登录证明、恢复授权和恢复密钥轮换。
- SHA-256：设备 ID 和摘要。
- AES-GCM：客户端私钥静态加密。
- HMAC-SHA-256：本机绑定标签。
- 登录签名包含协议域、会话 ID、服务器随机数、服务器 ID、玩家名、认证模式、设备标签及公钥，并采用定长类型标记和长度前缀编码。
- 登录挑战短期有效且一次性消费；账户修改还绑定 `authRevision`。

服务端不会在 Netty 网络线程执行玩家 JSON 读写或主要验签工作。认证使用 1–2 个后台线程和有界 128 项队列，避免恶意连接无限制造任务；每个玩家账户的读取、校验、修改和保存采用独立锁，不会把所有玩家串行化。客户端仅在登录时做少量本地文件读取、DPAPI/AES-GCM 和 Ed25519 操作，正常游戏 Tick 没有持续设备指纹扫描。

## 安全边界

- 用户名允许被抢注是当前产品边界；真正的控制权由已登记设备、恢复密钥和服务器玩家数据共同决定。
- 攻击者若取得正在使用的系统账户权限或有效恢复私钥，可以冒充玩家。
- HTTP 管理接口在没有可信反向代理时不防窃听；需要公网使用时应优先配置 HTTPS。
- 本机绑定主要阻止“复制整合包即可复制身份”，不等同于 TPM/安全芯片级不可导出密钥。
- 服务器首次建立全新玩家记录时会自动接受首台设备，因此仍建议配合白名单或其他注册策略。

## 构建

```powershell
$env:JAVA_HOME='C:\Program Files\Java\jdk-17'
.\gradlew.bat build --offline --no-daemon
```

构建产物位于 `build/libs/`。

## 许可与致谢

本项目沿用 GPLv3。感谢原作者 Jissee 的 [JarsAuth](https://github.com/Jissee/JarsAuth) 项目；本仓库是社区修改版，不是原作者的官方发行版。
