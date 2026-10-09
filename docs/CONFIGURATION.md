# 配置与部署

设备认证配置位于世界根目录的 `setting-client-auth.json`。文件首次生成时 `enabled=false`；只做设备认证时，不需要开启文件校验或服务器许可证。

## 先在本机验证

下面是只允许服务器本机访问审批网页的示例：

```json
{
  "enabled": true,
  "interval": 10,
  "timeout": 5,
  "approvalPort": 8787,
  "approvalBindHost": "127.0.0.1",
  "approvalPublicBaseUrl": "http://127.0.0.1:8787",
  "approvalPermissionLevel": 4,
  "approvalExpireMinutes": 30
}
```

默认监听地址为 `0.0.0.0`，如果只在本机审批，应主动改成示例中的 `127.0.0.1`。保存后执行 `/jarsauth reload`；控制台执行时去掉 `/`。

| 配置 | 用途 |
| --- | --- |
| `enabled` | 启用进入世界前的设备认证 |
| `approvalBindHost` / `approvalPort` | 审批 HTTP 服务的监听地址和端口 |
| `approvalPublicBaseUrl` | 生成管理员实际访问的审批链接 |
| `approvalPermissionLevel` | 接收审批消息的玩家权限等级；管理命令本身固定要求等级 4 |
| `approvalExpireMinutes` | 待审批请求的有效期 |
| `interval` / `timeout` | 保留的历史字段；当前登录挑战有效期由代码固定为 25 秒，修改它们不会改变登录超时 |

管理员通过游戏内消息获得批准 / 拒绝链接，或执行 `/jarsauth pending`、`approve`、`reject`。玩家申请或审批后需要重新连接服务器。

## 跨机器与公网审批

本机地址 `127.0.0.1` 不能让另一台电脑直接访问服务端。远程审批时，需要把 `approvalPublicBaseUrl` 设置为管理员能够访问的地址，并配置对应的网络入口。

```text
管理员浏览器 --HTTPS--> 反向代理或受保护的隧道 --HTTP--> 审批端口
```

内置服务只提供 HTTP，TLS 需要由 Nginx、Caddy、Cloudflare 等上游处理。单纯把 HTTP 端口通过 FRP TCP 转发，并不会自动变成 HTTPS。原始审批端口应仅允许可信代理或管理网络访问。

审批链接带有一次性令牌，持有完整链接的人可以批准或拒绝对应请求。不要公开转发，也不要让代理日志记录完整 URL。

Minecraft 的 SRV 记录只用于查找游戏端口，不能转发审批网页。游戏入口与审批入口分别配置。

## 数据与升级

- 一起备份世界目录中的服务器身份文件、玩家设备数据和配置。服务端身份改变后，原恢复备份无法用于新的服务器身份。
- 客户端共享数据目录与恢复备份路径见 [README](../README.md)。
- `5.x` 的 UUID 设备凭据不会自动迁移。升级前安排重新登记，不能把旧凭据当成 `6.x` 恢复备份。
- 原版的文件校验与许可证功能仍保留；完整配置说明会随服务端启动提取到世界目录。`/jarsauth record` 用于记录文件校验基准，不会关闭本版的设备登录认证。
