/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.client_auth.Codec;
import me.jissee.jarsauth.client_auth.DataUtil;
import me.jissee.jarsauth.client_auth.DeviceIdentity;
import me.jissee.jarsauth.client_auth.DeviceRegistrationRequest;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkEvent;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

public class CABroadcastPacket {
    public static final int PUBLIC_KEY = 271827182;
    public static final int AUTH_INFO = 314159265;

    private static PrivateKey pri;

    private final String serverID;
    private final int type;
    private final byte[] payload;

    public CABroadcastPacket(String serverID, int type, byte[] payload) {
        this.serverID = serverID;
        this.type = type;
        this.payload = payload;
    }


    public void encode(FriendlyByteBuf buf){
        buf.writeUtf(serverID);
        buf.writeInt(type);
        buf.writeByteArray(payload);
    }
    public static CABroadcastPacket decode(FriendlyByteBuf buf){
        return new CABroadcastPacket(buf.readUtf(), buf.readInt(), buf.readByteArray());
    }
    public boolean handle(Supplier<NetworkEvent.Context> ctx){
        ctx.get().enqueueWork(()->{
            if(payload.length == 0){//register new
                sendRegistrationRequest();
            }else{//send auth info
                switch (type){
                    case AUTH_INFO://decrypt
                        try {
                            byte[] uuidEnc = payload;
                            byte[] decrypted = Codec.decrypt(uuidEnc, pri);
                            pri = null;
                            UUID uuid = Codec.bytesToUUID(decrypted);
                            String name = Compatibility.getStringName();
                            DataUtil.createAndSaveIdentity(serverID, name, uuid);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    case PUBLIC_KEY :
                        try {
                            String name = Compatibility.getStringName();
                            Optional<DeviceIdentity> identity = DataUtil.readDeviceIdentity(serverID, name);
                            if(identity.isEmpty()){
                                sendRegistrationRequest();
                                return;
                            }
                            byte[] uuidByteOrigin = Codec.uuidToBytes(identity.get().getDeviceId());
                            byte[] pub = payload;
                            PublicKey publicKey = Codec.byteArr2PublicKey(pub);
                            byte[] encrypted = Codec.encrypt(uuidByteOrigin, publicKey);
                            CAAuthPacket packet = new CAAuthPacket(serverID, CAAuthPacket.AUTH_INFO, encrypted);
                            Compatibility.sendToServer(packet);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                        break;
                }
            }
        });
        ctx.get().setPacketHandled(true);
        return true;
    }

    private void sendRegistrationRequest() {
        try {
            KeyPair pair = Codec.generateKeyPair();
            pri = pair.getPrivate();
            String name = Compatibility.getStringName();
            String label = DataUtil.suggestDeviceLabel(name);
            DeviceRegistrationRequest request = new DeviceRegistrationRequest(label, pair.getPublic().getEncoded());
            Compatibility.sendToServer(new CAAuthPacket(serverID, CAAuthPacket.REGISTER_DEVICE, request.encode()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
