/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.client_auth.LoginAuthManager;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkEvent;

import java.security.SecureRandom;
import java.util.UUID;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/** Server-to-client challenge sent before a ServerPlayer is created. */
public final class AuthLoginQuery implements IntSupplier {
    public static final int PROTOCOL = 2;
    private static final SecureRandom RANDOM = new SecureRandom();

    private int loginIndex;
    private final String sessionId;
    private final byte[] nonce;
    private final String serverId;
    private final long issuedAt;
    private final boolean enabled;

    /** Called by Forge once for every new login negotiation. */
    public AuthLoginQuery() {
        this.sessionId = UUID.randomUUID().toString();
        this.nonce = new byte[32];
        RANDOM.nextBytes(this.nonce);
        this.serverId = Settings.getServerID() == null ? "unavailable" : Settings.getServerID().getServerID();
        this.issuedAt = System.currentTimeMillis();
        this.enabled = Settings.getClientAuthSetting() != null && Settings.getClientAuthSetting().isEnabled();
        if (enabled) {
            LoginAuthManager.getInstance().rememberChallenge(sessionId, nonce, serverId, issuedAt);
        }
    }

    private AuthLoginQuery(int loginIndex, String sessionId, byte[] nonce, String serverId, long issuedAt, boolean enabled) {
        this.loginIndex = loginIndex;
        this.sessionId = sessionId;
        this.nonce = nonce;
        this.serverId = serverId;
        this.issuedAt = issuedAt;
        this.enabled = enabled;
    }

    public static void encode(AuthLoginQuery message, FriendlyByteBuf buf) {
        buf.writeInt(PROTOCOL);
        buf.writeUtf(message.sessionId, 64);
        buf.writeByteArray(message.nonce);
        buf.writeUtf(message.serverId, 256);
        buf.writeLong(message.issuedAt);
        buf.writeBoolean(message.enabled);
    }

    public static AuthLoginQuery decode(FriendlyByteBuf buf) {
        int protocol = buf.readInt();
        if (protocol != PROTOCOL) {
            throw new IllegalArgumentException("Unsupported JarsAuth login protocol " + protocol);
        }
        return new AuthLoginQuery(0, buf.readUtf(64), buf.readByteArray(64), buf.readUtf(256), buf.readLong(), buf.readBoolean());
    }

    public static void handle(AuthLoginQuery message, Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        try {
            AuthLoginResponse response = ClientLoginAuth.createResponse(message);
            response.setLoginIndex(message.getAsInt());
            PacketHandler.reply(response, context);
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

    public String getSessionId() {
        return sessionId;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public String getServerId() {
        return serverId;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
