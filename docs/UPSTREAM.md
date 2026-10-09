# 代码来源与独立维护范围

本项目由 KKBK-233 独立维护，基于 [Jissee/JarsAuth](https://github.com/Jissee/JarsAuth) 的 Forge 分支开发，继续保留上游 Git 历史、版权标识和许可文件。

## 本次对照基准

- 上游 Forge 分支：[`53fc1bdd5da891ec114d5614810c7a92e03d74a3`](https://github.com/Jissee/JarsAuth/commit/53fc1bdd5da891ec114d5614810c7a92e03d74a3)，版本 `5.0`。
- 本仓库修改前：[`a1c0b9653646c4f86830ab57284b5a3ff541b9e5`](https://github.com/KKBK-233/JarsAuth-DeviceApproval/commit/a1c0b9653646c4f86830ab57284b5a3ff541b9e5)，版本 `6.1.1`。
- 上游提交存在于本仓库历史中，可以直接执行 `git diff 53fc1bd a1c0b96 -- src/main/java` 复核。

对上述两个提交的 `src/main/java` 文件逐个比较：当前 44 个 Java 文件中，16 个与上游内容完全一致，14 个为上游文件的修改版，14 个为新增文件。该统计描述文件来源，不代表贡献比例或功能价值。

## 仍保留并使用的上游实现

| 功能 | 代表代码 | 保留情况 |
| --- | --- | --- |
| 客户端文件校验 | `file_checksum/FCPendingList.java`、`packet/FCAuthPacket.java`、`packet/FCBroadcastPacket.java` | 校验主体仍在；两个网络包文件与上游完全一致 |
| 服务器许可证 | `server_license/SLPendingList.java`、`server_license/ServerLicense.java` | 保留许可证业务；后台推进方式和持久化格式已经调整 |
| 许可证管理界面 | `server_license/gui/` | 多数文件与上游完全一致，发行 JAR 仍保留工具入口 |
| 服务器身份和配置 | `server_settings/ServerID.java`、`ClientDetail.java`、`SettingFileChecksum.java`、`SettingServerLicense.java` | 上述文件与上游完全一致；设备认证仍使用服务器身份 |
| Forge 接入与公共管理 | `JarsAuth.java`、`event/EventHandler.java`、`command/ModCommand.java` | 基于上游修改，继续承担事件接入与命令注册 |

这些并非仅剩的文件名或空壳：`EventHandler` 仍加载上述配置、调用文件校验与许可证流程，设备登录和恢复作用域也仍依赖 `ServerID`。

## 本分支重写或新增的部分

- 进入世界前的设备登录协商：`LoginAuthManager`、`AuthLoginQuery`、`AuthLoginResponse`、`ClientLoginAuth`。
- 设备与恢复身份：`CryptoV2`、`ClientCredentialStore`、`PlayerDevices`。
- 新设备审批：新增 `ApprovalHttpServer`，重写 `CAPendingList`。
- 玩家设备管理与恢复轮换：`RecoveryOperationManager` 及相关网络包。
- 服务器许可证由旧二进制形式改为 JSON，并增加对应回归测试。

## 名称与许可

对外名称为 **JarsAuth Device Approval**，维护人为 **KKBK-233**，原始代码作者保留 **Jissee and contributors**。内部 `jarsauth` 模组 ID、`me.jissee.jarsauth` 包名和现有数据路径用于兼容，不代表本分支是原作者的官方发行。

继续保留 [LICENCE.txt](../LICENCE.txt) 和 [ADDITIONAL-LICENCE.txt](../ADDITIONAL-LICENCE.txt)。后者的禁止网易版条款也来自上述上游提交；本次没有擅自移除、改写或声称已解决它与 GPLv3 的适用关系。

设备认证已经大量重写，但当前仍有上游的实际功能代码，因此不能把整个项目声明为与上游无关的全新作品。
