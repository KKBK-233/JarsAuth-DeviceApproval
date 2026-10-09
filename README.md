# JarsAuth Device Approval

**Minecraft 1.20.1 Forge 服务器的免输密码登录与新设备审批模组。**

玩家用登记过的电脑直接登录，无需每次进入游戏后输入密码。换电脑时，有自己的恢复备份就能重新登记；没有备份的设备由管理员审批。适合需要管理玩家登录设备、OP 无法全天在线的小型 Forge 服务器，**客户端和服务端都要安装**。

## 能帮服主解决什么

| 你遇到的问题 | 这个模组怎么处理 |
| --- | --- |
| 玩家每次登录都要输密码，忘记了又来找服主 | 已登记设备自动验证，正常连接服务器即可 |
| 有人知道老玩家的名字，想从另一台电脑冒充登录 | 已建立账户的新设备需要恢复备份或管理员批准；未通过验证进不了世界 |
| 玩家换电脑时 OP 不在线，只能一直等 | 提前保存恢复备份，换电脑后自行登记新设备 |
| 整合包被复制或转发，担心登录身份也跟着流出 | 登录凭据保存在系统用户目录，并做本机校验，减少随整合包复制身份的风险 |
| 玩家不再使用某台电脑 | 玩家可以查看、重命名和撤销自己的设备，下次连接时生效 |

**首次登记会自动接受新玩家的第一台设备，不能阻止用户名抢注。**正式开服前建议配合白名单。拿到有效恢复备份或控制玩家系统账户的人仍能冒充玩家。

## 版本与安装

当前版本：**6.1.2**。

| 项目 | 要求与验证范围 |
| --- | --- |
| Minecraft | Java 版 **1.20.1** |
| 加载器 | Forge **47.x**，构建基于 **47.4.13**；其他 47.x 尚未逐版本回归 |
| Java | **17** |
| 安装位置 | 客户端与独立服务端的 `mods/`，使用完全相同的 JAR |
| 其他环境 | 尚未适配 Fabric、Quilt、NeoForge、Paper / Spigot 或其他 Minecraft 版本 |

1. 从本仓库的 [Releases](https://github.com/KKBK-233/JarsAuth-DeviceApproval/releases) 获取发行包；尚无对应发行版本时，可按文末步骤自行构建。
2. 客户端和服务端各放入一份 `JarsAuth-DeviceApproval-forge-1.20.1-6.1.2.jar`。先移除旧版或原版 JarsAuth JAR，避免重复加载。
3. 启动一次独立服务端，生成配置。**默认关闭设备认证**，在世界根目录的 `setting-client-auth.json` 中把 `enabled` 改成 `true`。
4. 如果只在服务器本机使用审批网页，同时把 `approvalBindHost` 改成 `127.0.0.1`。保存后在控制台执行 `jarsauth reload`，或在游戏中执行 `/jarsauth reload`。
5. 让一个白名单测试玩家连接，保存自动生成的恢复备份，再验证换设备与管理员审批流程。

认证在进入世界前完成。启用后，缺少模组、未登记或未获批准的设备不能进入服务器。`6.x` 不自动迁移 `5.x` 的旧 UUID 设备凭据；升级前备份服务器数据，并安排玩家重新登记。

## 玩家换电脑，OP 不在线怎么办

首次登记成功后，客户端会在共享数据目录的 `recovery-backups/` 中生成属于该服务器和玩家的恢复备份。

| 系统 | 共享数据目录 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\JarsAuth` |
| Linux | `$XDG_DATA_HOME/JarsAuth`，未设置时为 `~/.local/share/JarsAuth` |
| macOS | `~/Library/Application Support/JarsAuth` |

1. 在旧电脑上单独保存自己的完整恢复备份文件。
2. 把备份放到新电脑共享数据目录下的 `recovery-import/` 文件夹。
3. 使用对应玩家名连接原服务器，新设备验证成功后即可进入世界，无需等 OP 批准。

**恢复备份相当于该玩家的换机通行证。**不要把它放进公开整合包、分享网盘或聊天记录。没有有效备份时，先连接服务器生成待审批请求，管理员批准后再重连。

## 常用命令

玩家在游戏中使用：

```text
/jarsauth devices
/jarsauth device rename <设备ID或唯一前缀> <新名称>
/jarsauth device revoke <设备ID或唯一前缀>
/jarsauth recovery rotate
```

设备管理和恢复备份轮换需要当前玩家的有效恢复凭据。撤销当前设备不会立即踢出在线会话，但会阻止其下次登录；轮换成功后旧恢复备份失效，请保存新备份。

管理员使用：

```text
/jarsauth pending
/jarsauth approve <requestId>
/jarsauth reject <requestId>
/jarsauth reload
```

控制台执行时去掉开头的 `/`。这些管理命令要求权限等级 4；待审批记录会保存在服务器数据中，重启后重新建立审批请求。

管理员也可以使用游戏内收到的审批网页链接。内置网页只提供 HTTP：跨机器或公网访问时，需要正确设置 `approvalPublicBaseUrl`，并通过 HTTPS 反向代理或受保护的隧道访问。**拿到完整审批链接的人可以执行该次审批，不要公开转发。**具体配置见 [配置与部署](docs/CONFIGURATION.md)。

## 使用范围与反馈

- 它管理的是玩家登录设备，不替代正版验证、白名单或服务器日常维护。
- 同一系统账户上的多个启动器实例默认共享设备数据；不要把共享电脑账户视为不同玩家的隔离边界。
- 恢复备份只对应一个服务器和玩家。服务器的身份文件与玩家数据需要一起备份，恢复时不要随意更换服务器 ID。
- Windows、Linux、macOS 均有客户端存储实现；完整跨平台联机流程仍需实测。
- 本仓库保留原版的可选文件校验和服务器许可证功能，默认关闭。只用设备认证时无需开启它们。

发现问题请提交到 [本仓库 Issues](https://github.com/KKBK-233/JarsAuth-DeviceApproval/issues)，附上 Minecraft、Forge、Java 与模组版本、复现步骤及相关日志。不要提交恢复备份、私钥或完整审批链接。

## 构建与验证

安装 JDK 17，首次构建需要网络下载依赖：

```powershell
$env:JAVA_HOME='C:\Program Files\Java\jdk-17'
.\gradlew.bat build --no-daemon
```

Linux / macOS 使用 `sh ./gradlew build --no-daemon`。依赖缓存齐全时可增加 `--offline`；产物位于 `build/libs/`。

现有自动测试覆盖服务器许可证 JSON 持久化及忽略旧二进制文件。构建通过不代表完整登录流程已验收；公开稳定版发布前还需完成 [联机验收](docs/RELEASE.md)。实现与安全边界见 [技术说明](docs/SECURITY.md)。

## 维护与代码来源

本项目由 **KKBK-233 独立维护**，基于 **Jissee/JarsAuth** 开发，与原作者的官方发行版分别维护。

设备登录、恢复备份和审批机制已重写或新增，但文件校验、服务器许可证、管理界面及配置等代码仍保留上游实现，因此继续保留原作者署名、历史与许可文件。详细对照见 [代码来源](docs/UPSTREAM.md)。

仓库保留 [GPLv3 原文](LICENCE.txt) 及上游的 [附加许可条款](ADDITIONAL-LICENCE.txt)。后者包含禁止用于网易版的限制，其与 GPLv3 的适用关系仍需厘清；不能把当前许可状态描述为已完成平台审核。
