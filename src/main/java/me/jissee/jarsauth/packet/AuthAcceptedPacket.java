/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.packet;

import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.client_auth.ClientCredentialStore;
import net.minecraft.client.Minecraft;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraftforge.network.NetworkEvent;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Supplier;

/** Confirms that the protected local device/recovery keys were accepted. */
public final class AuthAcceptedPacket {
    private static final Logger LOGGER = LogUtils.getLogger();

    private final String serverId;
    private final String playerName;
    private final String accountId;
    private final String deviceId;
    private final byte[] recoveryPublicKey;

    public AuthAcceptedPacket(String serverId, String playerName, String accountId,
                              String deviceId, byte[] recoveryPublicKey) {
        this.serverId = serverId;
        this.playerName = playerName;
        this.accountId = accountId;
        this.deviceId = deviceId == null ? "" : deviceId;
        this.recoveryPublicKey = recoveryPublicKey == null ? new byte[0] : recoveryPublicKey.clone();
    }

    public static void encode(AuthAcceptedPacket message, FriendlyByteBuf buf) {
        buf.writeUtf(message.serverId, 256);
        buf.writeUtf(message.playerName, 64);
        buf.writeUtf(message.accountId, 64);
        buf.writeUtf(message.deviceId, 128);
        buf.writeByteArray(message.recoveryPublicKey);
    }

    public static AuthAcceptedPacket decode(FriendlyByteBuf buf) {
        return new AuthAcceptedPacket(
                buf.readUtf(256), buf.readUtf(64), buf.readUtf(64), buf.readUtf(128), buf.readByteArray(1024)
        );
    }

    public static void handle(AuthAcceptedPacket message, Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        context.enqueueWork(() -> {
            try {
                Minecraft minecraft = Minecraft.getInstance();
                ClientCredentialStore store = ClientLoginAuth.getStore(minecraft.gameDirectory.toPath());
                store.markDeviceAccepted(message.serverId, message.playerName);
                Optional<String> recoveryCode = store.onServerAccepted(
                        message.serverId, message.playerName, message.recoveryPublicKey
                );
                if (recoveryCode.isPresent()) {
                    Path backup = store.saveRecoveryBackup(
                            message.serverId, message.playerName, recoveryCode.get()
                    );
                    LOGGER.info("JarsAuth recovery backup created at {}", backup);
                    if (minecraft.player != null) {
                        minecraft.player.displayClientMessage(Component.literal(
                                "JarsAuth recovery key saved to " + backup + ". Copy it to a safe place."
                        ), false);
                    }
                }
            } catch (Exception e) {
                LOGGER.error("Could not finalize JarsAuth client credentials", e);
            }
        });
        context.setPacketHandled(true);
    }
}
