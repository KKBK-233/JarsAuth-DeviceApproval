/* This file is part of JarsAuth, licensed under GPLv3. */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.client_auth.RecoveryOperationManager;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.NetworkEvent;

import java.util.function.Supplier;

public final class RecoveryOperationResponse {
    private final String requestId;
    private final byte[] signature;
    private final byte[] newRecoveryPublicKey;
    private final byte[] newRecoverySignature;

    public RecoveryOperationResponse(String requestId, byte[] signature) {
        this(requestId, signature, new byte[0], new byte[0]);
    }

    public RecoveryOperationResponse(String requestId, byte[] signature,
                                     byte[] newRecoveryPublicKey, byte[] newRecoverySignature) {
        this.requestId = requestId;
        this.signature = signature == null ? new byte[0] : signature.clone();
        this.newRecoveryPublicKey = newRecoveryPublicKey == null ? new byte[0] : newRecoveryPublicKey.clone();
        this.newRecoverySignature = newRecoverySignature == null ? new byte[0] : newRecoverySignature.clone();
    }

    public static void encode(RecoveryOperationResponse message, FriendlyByteBuf buf) {
        buf.writeUtf(message.requestId, 64);
        buf.writeByteArray(message.signature);
        buf.writeByteArray(message.newRecoveryPublicKey);
        buf.writeByteArray(message.newRecoverySignature);
    }

    public static RecoveryOperationResponse decode(FriendlyByteBuf buf) {
        return new RecoveryOperationResponse(
                buf.readUtf(64), buf.readByteArray(1024), buf.readByteArray(1024), buf.readByteArray(1024)
        );
    }

    public static void handle(RecoveryOperationResponse message, Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        context.enqueueWork(() -> {
            ServerPlayer player = context.getSender();
            if (player != null) {
                RecoveryOperationManager.getInstance().handle(message, player);
            }
        });
        context.setPacketHandled(true);
    }

    public String getRequestId() { return requestId; }
    public byte[] getSignature() { return signature.clone(); }
    public byte[] getNewRecoveryPublicKey() { return newRecoveryPublicKey.clone(); }
    public byte[] getNewRecoverySignature() { return newRecoverySignature.clone(); }
}
