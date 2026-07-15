/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.client_auth.CAPendingList;
import me.jissee.jarsauth.client_auth.Codec;
import me.jissee.jarsauth.client_auth.DeviceRegistrationRequest;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.NetworkEvent;

import java.security.PublicKey;
import java.util.function.Supplier;

public class CAAuthPacket {
    public static final int PUBLIC_KEY = 314159265;
    public static final int AUTH_INFO = 271828172;
    public static final int REGISTER_DEVICE = 141421356;

    private final String serverID;
    private final int type;
    private final byte[] payload;

    public CAAuthPacket(String serverID, int type, byte[] payload){
        this.serverID = serverID;
        this.type = type;
        this.payload = payload;
    }

    public void encode(FriendlyByteBuf buf){
        buf.writeUtf(serverID);
        buf.writeInt(type);
        buf.writeByteArray(payload);
    }
    public static CAAuthPacket decode(FriendlyByteBuf buf){
        return new CAAuthPacket(buf.readUtf(), buf.readInt(), buf.readByteArray());
    }
    public boolean handle(Supplier<NetworkEvent.Context> ctx){
        ctx.get().enqueueWork(()->{
            if(!Settings.getServerID().getServerID().equals(serverID)){
                return;
            }
            switch (type){
                case REGISTER_DEVICE:
                    try{
                        ServerPlayer plr = ctx.get().getSender();
                        if(plr == null){
                            return;
                        }
                        DeviceRegistrationRequest request = DeviceRegistrationRequest.decode(payload);
                        CAPendingList.getInstance().handleRegisterRequest(serverID, plr, request);
                    }catch(Exception e){
                        throw new RuntimeException(e);
                    }
                    break;
                case AUTH_INFO:
                    ServerPlayer plr = ctx.get().getSender();
                    if(plr != null){
                        CAPendingList.getInstance().addAuthInfo(serverID, plr, payload);
                    }
                    break;
            }
        });
        ctx.get().setPacketHandled(true);
        return true;
    }
}
