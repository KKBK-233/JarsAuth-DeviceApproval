/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.client_auth.AuthMode;
import me.jissee.jarsauth.client_auth.LoginAuthManager;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.HandshakeHandler;
import net.minecraftforge.network.NetworkEvent;

import java.util.function.IntSupplier;
import java.util.function.Supplier;

/** Client proof returned as the indexed reply to {@link AuthLoginQuery}. */
public final class AuthLoginResponse implements IntSupplier {
    private int loginIndex;
    private final boolean enabled;
    private final String sessionId;
    private final AuthMode mode;
    private final String playerName;
    private final String deviceLabel;
    private final byte[] devicePublicKey;
    private final byte[] deviceSignature;
    private final byte[] recoveryPublicKey;
    private final byte[] recoverySignature;
    private final byte[] legacySecret;

    public AuthLoginResponse(
            boolean enabled,
            String sessionId,
            AuthMode mode,
            String playerName,
            String deviceLabel,
            byte[] devicePublicKey,
            byte[] deviceSignature,
            byte[] recoveryPublicKey,
            byte[] recoverySignature,
            byte[] legacySecret
    ) {
        this.enabled = enabled;
        this.sessionId = sessionId;
        this.mode = mode;
        this.playerName = playerName;
        this.deviceLabel = deviceLabel;
        this.devicePublicKey = copy(devicePublicKey);
        this.deviceSignature = copy(deviceSignature);
        this.recoveryPublicKey = copy(recoveryPublicKey);
        this.recoverySignature = copy(recoverySignature);
        this.legacySecret = copy(legacySecret);
    }

    private static byte[] copy(byte[] value) {
        return value == null ? new byte[0] : value.clone();
    }

    public static void encode(AuthLoginResponse message, FriendlyByteBuf buf) {
        buf.writeBoolean(message.enabled);
        buf.writeUtf(message.sessionId, 64);
        buf.writeByte(message.mode.ordinal());
        buf.writeUtf(message.playerName, 64);
        buf.writeUtf(message.deviceLabel, 64);
        buf.writeByteArray(message.devicePublicKey);
        buf.writeByteArray(message.deviceSignature);
        buf.writeByteArray(message.recoveryPublicKey);
        buf.writeByteArray(message.recoverySignature);
        buf.writeByteArray(message.legacySecret);
    }

    public static AuthLoginResponse decode(FriendlyByteBuf buf) {
        boolean enabled = buf.readBoolean();
        String sessionId = buf.readUtf(64);
        int mode = buf.readUnsignedByte();
        if (mode < 0 || mode >= AuthMode.values().length) {
            throw new IllegalArgumentException("Invalid JarsAuth mode " + mode);
        }
        return new AuthLoginResponse(
                enabled,
                sessionId,
                AuthMode.values()[mode],
                buf.readUtf(64),
                buf.readUtf(64),
                buf.readByteArray(1024),
                buf.readByteArray(1024),
                buf.readByteArray(1024),
                buf.readByteArray(1024),
                buf.readByteArray(64)
        );
    }

    public static void handle(HandshakeHandler handler, AuthLoginResponse message, Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        try {
            LoginAuthManager.getInstance().handleResponse(message, context.getNetworkManager());
        } finally {
            context.setPacketHandled(true);
        }
    }

    @Override
    public int getAsInt() {
        return loginIndex;
    }

    public void setLoginIndex(int loginIndex) {
        this.loginIndex = loginIndex;
    }

    public boolean isEnabled() { return enabled; }
    public String getSessionId() { return sessionId; }
    public AuthMode getMode() { return mode; }
    public String getPlayerName() { return playerName; }
    public String getDeviceLabel() { return deviceLabel; }
    public byte[] getDevicePublicKey() { return devicePublicKey.clone(); }
    public byte[] getDeviceSignature() { return deviceSignature.clone(); }
    public byte[] getRecoveryPublicKey() { return recoveryPublicKey.clone(); }
    public byte[] getRecoverySignature() { return recoverySignature.clone(); }
    public byte[] getLegacySecret() { return legacySecret.clone(); }
}
