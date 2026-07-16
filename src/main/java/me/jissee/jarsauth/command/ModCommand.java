/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.client_auth.CAPendingList;
import me.jissee.jarsauth.client_auth.PlayerDevices;
import me.jissee.jarsauth.client_auth.RecoveryOperation;
import me.jissee.jarsauth.client_auth.RecoveryOperationManager;
import me.jissee.jarsauth.event.EventHandler;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.loading.FMLLoader;

public class ModCommand {
    @SubscribeEvent
    public static void onRegisterCommand(RegisterCommandsEvent event) {
        LiteralArgumentBuilder<CommandSourceStack> jarsAuth = Commands.literal("jarsauth");

        jarsAuth.then(Commands.literal("record")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .executes(src -> {
                    var recording = EventHandler
                            .ifThisVariableIsTrueThenTheServerIsInRecordingModeOtherwiseTheServerIsInAuthenticatingMode();
                    recording.set(!recording.get());
                    Compatibility.consoleMessage(src, Compatibility.translatable(
                            recording.get() ? "text.record.on" : "text.record.off"));
                    return 0;
                }));

        jarsAuth.then(Commands.literal("reload")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .executes(src -> {
                    EventHandler.reloadSettings();
                    EventHandler.reloadDetails();
                    return 0;
                }));

        jarsAuth.then(Commands.literal("pending")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .executes(src -> {
                    var pending = CAPendingList.getInstance().listPendingApprovals();
                    if (pending.isEmpty()) {
                        Compatibility.consoleMessage(src, Component.translatable("text.caauth.pending.empty"));
                        return 0;
                    }
                    for (var approval : pending) {
                        Compatibility.consoleMessage(src, Component.literal("%s | %s | %s".formatted(
                                approval.getRequestId(), approval.getPlayerName(), approval.getDeviceLabel())));
                    }
                    return pending.size();
                }));

        jarsAuth.then(Commands.literal("approve")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .then(Commands.argument("requestId", StringArgumentType.word()).executes(src -> {
                    String requestId = StringArgumentType.getString(src, "requestId");
                    boolean approved = CAPendingList.getInstance().approvePendingByRequestId(requestId);
                    Compatibility.consoleMessage(src, Component.translatable(
                            approved ? "text.caauth.command.approve.ok" : "text.caauth.command.approve.fail",
                            requestId));
                    return approved ? 1 : 0;
                })));

        jarsAuth.then(Commands.literal("reject")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .then(Commands.argument("requestId", StringArgumentType.word()).executes(src -> {
                    String requestId = StringArgumentType.getString(src, "requestId");
                    boolean rejected = CAPendingList.getInstance().rejectPendingByRequestId(requestId);
                    Compatibility.consoleMessage(src, Component.translatable(
                            rejected ? "text.caauth.command.reject.ok" : "text.caauth.command.reject.fail",
                            requestId));
                    return rejected ? 1 : 0;
                })));

        jarsAuth.then(Commands.literal("devices").executes(src -> {
            var player = src.getSource().getPlayerOrException();
            var devices = PlayerDevices.load(player.getName().getString()).orElse(null);
            if (devices == null || devices.getDevices().isEmpty()) {
                Compatibility.consoleMessage(src, Component.literal("JarsAuth: no devices"));
                return 0;
            }
            for (var device : devices.getDevices()) {
                String id = device.getDeviceId() == null ? "legacy" : device.getDeviceId();
                Compatibility.consoleMessage(src, Component.literal("%s | %s | %s".formatted(
                        id, device.getStatus(), device.getLabel())));
            }
            return devices.getDevices().size();
        }));

        jarsAuth.then(Commands.literal("device")
                .then(Commands.literal("revoke")
                        .then(Commands.argument("deviceId", StringArgumentType.word()).executes(src -> {
                            var player = src.getSource().getPlayerOrException();
                            boolean sent = RecoveryOperationManager.getInstance().request(
                                    player, RecoveryOperation.REVOKE_DEVICE,
                                    StringArgumentType.getString(src, "deviceId"), "");
                            return sent ? 1 : 0;
                        })))
                .then(Commands.literal("rename")
                        .then(Commands.argument("deviceId", StringArgumentType.word())
                                .then(Commands.argument("label", StringArgumentType.greedyString()).executes(src -> {
                                    var player = src.getSource().getPlayerOrException();
                                    boolean sent = RecoveryOperationManager.getInstance().request(
                                            player, RecoveryOperation.RENAME_DEVICE,
                                            StringArgumentType.getString(src, "deviceId"),
                                            StringArgumentType.getString(src, "label"));
                                    return sent ? 1 : 0;
                                })))));

        jarsAuth.then(Commands.literal("recovery")
                .then(Commands.literal("rotate").executes(src -> {
                    var player = src.getSource().getPlayerOrException();
                    boolean sent = RecoveryOperationManager.getInstance().request(
                            player, RecoveryOperation.ROTATE_RECOVERY, "", "");
                    return sent ? 1 : 0;
                })));

        jarsAuth.then(Commands.literal("help")
                .requires(req -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                .executes(src -> {
                    Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth record  开关记录模式"));
                    Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth reload  重新加载配置"));
                    Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth pending  查看待审批设备"));
                    Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth approve <requestId>  批准设备"));
                    Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth reject <requestId>  拒绝设备"));
                    return 0;
                }));

        event.getDispatcher().register(jarsAuth);
    }
}
