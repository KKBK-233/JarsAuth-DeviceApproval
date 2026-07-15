/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.client_auth.CAPendingList;
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
        LiteralArgumentBuilder<CommandSourceStack> JARSAUTH = Commands.literal("jarsauth");

        JARSAUTH.then(
                Commands.literal("record").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .executes((src) -> {
                            if (EventHandler.ifThisVariableIsTrueThenTheServerIsInRecordingModeOtherwiseTheServerIsInAuthenticatingMode().get()) {
                                EventHandler.ifThisVariableIsTrueThenTheServerIsInRecordingModeOtherwiseTheServerIsInAuthenticatingMode().set(false);
                                Compatibility.consoleMessage(src, Compatibility.translatable("text.record.off"));
                            } else {
                                EventHandler.ifThisVariableIsTrueThenTheServerIsInRecordingModeOtherwiseTheServerIsInAuthenticatingMode().set(true);
                                Compatibility.consoleMessage(src, Compatibility.translatable("text.record.on"));
                            }
                            return 0;
                        })
        );
        JARSAUTH.then(
                Commands.literal("reload").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .executes((src) -> {
                            EventHandler.reloadSettings();
                            EventHandler.reloadDetails();
                            return 0;
                        })
        );
        JARSAUTH.then(
                Commands.literal("pending").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .executes((src) -> {
                            var pending = CAPendingList.getInstance().listPendingApprovals();
                            if (pending.isEmpty()) {
                                Compatibility.consoleMessage(src, Component.translatable("text.caauth.pending.empty"));
                                return 0;
                            }
                            for (var approval : pending) {
                                Compatibility.consoleMessage(
                                        src,
                                        Component.literal("%s | %s | %s".formatted(
                                                approval.getRequestId(),
                                                approval.getPlayerName(),
                                                approval.getDeviceLabel()
                                        ))
                                );
                            }
                            return pending.size();
                        })
        );
        JARSAUTH.then(
                Commands.literal("approve").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .then(Commands.argument("requestId", StringArgumentType.word())
                                .executes((src) -> {
                                    String requestId = StringArgumentType.getString(src, "requestId");
                                    boolean approved = CAPendingList.getInstance().approvePendingByRequestId(requestId);
                                    Compatibility.consoleMessage(src, Component.translatable(
                                            approved ? "text.caauth.command.approve.ok" : "text.caauth.command.approve.fail",
                                            requestId
                                    ));
                                    return approved ? 1 : 0;
                                }))
        );
        JARSAUTH.then(
                Commands.literal("reject").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .then(Commands.argument("requestId", StringArgumentType.word())
                                .executes((src) -> {
                                    String requestId = StringArgumentType.getString(src, "requestId");
                                    boolean rejected = CAPendingList.getInstance().rejectPendingByRequestId(requestId);
                                    Compatibility.consoleMessage(src, Component.translatable(
                                            rejected ? "text.caauth.command.reject.ok" : "text.caauth.command.reject.fail",
                                            requestId
                                    ));
                                    return rejected ? 1 : 0;
                                }))
        );
        JARSAUTH.then(
                Commands.literal("help").requires((req) -> FMLLoader.getDist().isDedicatedServer() && req.hasPermission(4))
                        .executes((src) -> {
                            Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth record  开关记录模式"));
                            Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth reload  重新加载配置"));
                            Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth pending  查看待审批设备"));
                            Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth approve <requestId>  批准设备"));
                            Compatibility.consoleMessage(src, Compatibility.literal("/jarsauth reject <requestId>  拒绝设备"));
                            return 0;
                        })
        );
        event.getDispatcher().register(JARSAUTH);
    }
}
