/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.packet;

import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.HandshakeHandler;
import net.minecraftforge.network.PacketDistributor;
import net.minecraftforge.network.simple.SimpleChannel;

import static me.jissee.jarsauth.JarsAuth.MODID;

public class PacketHandler {
    private static final String PROTOCOL_VERSION = "4";
    private static final SimpleChannel INSTANCE = NetworkRegistry.newSimpleChannel(
            new ResourceLocation(MODID,"message"),
            () -> PROTOCOL_VERSION,
            PROTOCOL_VERSION::equals,
            PROTOCOL_VERSION::equals
    );
    public static void register(){
        int i = 0;

        INSTANCE.registerMessage(
                i++,
                FCAuthPacket.class,
                FCAuthPacket::encode,
                FCAuthPacket::decode,
                FCAuthPacket::handle
        );

        INSTANCE.registerMessage(
                i++,
                FCBroadcastPacket.class,
                FCBroadcastPacket::encode,
                FCBroadcastPacket::decode,
                FCBroadcastPacket::handle
        );

        INSTANCE.messageBuilder(AuthLoginQuery.class, i++, NetworkDirection.LOGIN_TO_CLIENT)
                .encoder(AuthLoginQuery::encode)
                .decoder(AuthLoginQuery::decode)
                .consumerNetworkThread(AuthLoginQuery::handle)
                .loginIndex(AuthLoginQuery::getAsInt, AuthLoginQuery::setLoginIndex)
                .markAsLoginPacket()
                .add();

        INSTANCE.messageBuilder(AuthLoginResponse.class, i++, NetworkDirection.LOGIN_TO_SERVER)
                .encoder(AuthLoginResponse::encode)
                .decoder(AuthLoginResponse::decode)
                .consumerNetworkThread(HandshakeHandler.indexFirst(AuthLoginResponse::handle))
                .loginIndex(AuthLoginResponse::getAsInt, AuthLoginResponse::setLoginIndex)
                .add();

        INSTANCE.messageBuilder(AuthAcceptedPacket.class, i++, NetworkDirection.PLAY_TO_CLIENT)
                .encoder(AuthAcceptedPacket::encode)
                .decoder(AuthAcceptedPacket::decode)
                .consumerMainThread(AuthAcceptedPacket::handle)
                .add();

        INSTANCE.messageBuilder(RecoveryOperationRequest.class, i++, NetworkDirection.PLAY_TO_CLIENT)
                .encoder(RecoveryOperationRequest::encode)
                .decoder(RecoveryOperationRequest::decode)
                .consumerNetworkThread(RecoveryOperationRequest::handle)
                .add();

        INSTANCE.messageBuilder(RecoveryOperationResponse.class, i++, NetworkDirection.PLAY_TO_SERVER)
                .encoder(RecoveryOperationResponse::encode)
                .decoder(RecoveryOperationResponse::decode)
                .consumerNetworkThread(RecoveryOperationResponse::handle)
                .add();


    }

    public static <MSG> void sendToServer(MSG message) {
        INSTANCE.sendToServer(message);
    }

    public static <MSG> void sendToPlayer(MSG message, ServerPlayer player) {
        INSTANCE.send(PacketDistributor.PLAYER.with(() -> player), message);
    }

    public static <MSG> void reply(MSG message, NetworkEvent.Context context) {
        INSTANCE.reply(message, context);
    }
}
