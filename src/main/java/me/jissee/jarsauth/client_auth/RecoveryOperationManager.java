/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.client_auth;

import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.packet.AuthAcceptedPacket;
import me.jissee.jarsauth.packet.RecoveryOperationRequest;
import me.jissee.jarsauth.packet.RecoveryOperationResponse;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import org.slf4j.Logger;

import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Recovery-key authorized mutations for a player's own device list. */
public final class RecoveryOperationManager {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final long TTL_MS = Duration.ofSeconds(30).toMillis();
    private static final RecoveryOperationManager INSTANCE = new RecoveryOperationManager();

    private final Map<String, PendingOperation> pending = new ConcurrentHashMap<>();

    private RecoveryOperationManager() {
    }

    public static RecoveryOperationManager getInstance() {
        return INSTANCE;
    }

    public boolean request(ServerPlayer player, RecoveryOperation operation, String deviceIdOrPrefix, String label) {
        PlayerDevices devices = PlayerDevices.load(player.getName().getString()).orElse(null);
        if (devices == null || !devices.isV2() || devices.getRecoveryPublicKeyBytes() == null) {
            player.sendSystemMessage(Component.literal("JarsAuth recovery is not configured for this account"));
            return false;
        }
        String targetDeviceId = "";
        if (operation != RecoveryOperation.ROTATE_RECOVERY) {
            Optional<PlayerDevices.DeviceEntry> target = resolveDevice(devices, deviceIdOrPrefix);
            if (target.isEmpty()) {
                player.sendSystemMessage(Component.literal("JarsAuth device was not found or the prefix is ambiguous"));
                return false;
            }
            targetDeviceId = target.get().getDeviceId();
        }

        String requestId = UUID.randomUUID().toString();
        byte[] nonce = CryptoV2.randomBytes(32);
        long issuedAt = System.currentTimeMillis();
        PendingOperation value = new PendingOperation(
                requestId, player.getUUID(), player.getName().getString(), operation,
                targetDeviceId, label == null ? "" : label,
                nonce, issuedAt, devices.getAuthRevision()
        );
        pending.entrySet().removeIf(entry -> entry.getValue().playerId.equals(player.getUUID()));
        pending.put(requestId, value);
        Compatibility.sendModPacket(player, value.toPacket(Settings.getServerID().getServerID()));
        return true;
    }

    public void handle(RecoveryOperationResponse response, ServerPlayer player) {
        PendingOperation operation = pending.remove(response.getRequestId());
        if (operation == null || !operation.playerId.equals(player.getUUID()) || operation.isExpired()) {
            player.sendSystemMessage(Component.literal("JarsAuth recovery operation expired"));
            return;
        }
        synchronized (PlayerDevices.accountLock(operation.playerName)) {
            PlayerDevices devices = PlayerDevices.load(operation.playerName).orElse(null);
            if (devices == null || !devices.isV2() || devices.getAuthRevision() != operation.authRevision) {
                player.sendSystemMessage(Component.literal("JarsAuth device list changed; retry the operation"));
                return;
            }
            try {
                byte[] newRecoveryPublicKey = response.getNewRecoveryPublicKey();
                byte[] transcript = operation.transcript(
                        Settings.getServerID().getServerID(), newRecoveryPublicKey
                );
                PublicKey recoveryKey = CryptoV2.decodePublicKey(devices.getRecoveryPublicKeyBytes());
                if (!CryptoV2.verify(recoveryKey, transcript, response.getSignature())) {
                    player.sendSystemMessage(Component.literal("JarsAuth recovery signature is invalid or unavailable"));
                    return;
                }
                boolean changed = switch (operation.operation) {
                    case RENAME_DEVICE -> devices.renameDevice(operation.targetDeviceId, operation.label);
                    case REVOKE_DEVICE -> devices.revokeDevice(operation.targetDeviceId);
                    case ROTATE_RECOVERY -> rotateRecovery(devices, transcript, response);
                };
                if (!changed) {
                    player.sendSystemMessage(Component.literal("JarsAuth device operation did not change anything"));
                    return;
                }
                devices.save();
                if (operation.operation == RecoveryOperation.ROTATE_RECOVERY) {
                    Compatibility.sendModPacket(player, new AuthAcceptedPacket(
                            Settings.getServerID().getServerID(), operation.playerName,
                            devices.getAccountId().toString(), "", devices.getRecoveryPublicKeyBytes()
                    ));
                }
                player.sendSystemMessage(Component.literal("JarsAuth device operation completed"));
                LOGGER.info("Player {} completed recovery operation {} on device {}",
                        operation.playerName, operation.operation, operation.targetDeviceId);
            } catch (Exception e) {
                LOGGER.warn("Could not complete JarsAuth recovery operation for {}", operation.playerName, e);
                player.sendSystemMessage(Component.literal("JarsAuth recovery operation failed"));
            }
        }
    }

    private boolean rotateRecovery(PlayerDevices devices, byte[] transcript,
                                   RecoveryOperationResponse response) {
        byte[] publicKeyBytes = response.getNewRecoveryPublicKey();
        byte[] signature = response.getNewRecoverySignature();
        if (publicKeyBytes.length == 0 || signature.length == 0) {
            return false;
        }
        PublicKey newRecoveryKey = CryptoV2.decodePublicKey(publicKeyBytes);
        if (!CryptoV2.verify(newRecoveryKey, transcript, signature)) {
            return false;
        }
        if (java.security.MessageDigest.isEqual(devices.getRecoveryPublicKeyBytes(), publicKeyBytes)) {
            return false;
        }
        devices.enableV2(publicKeyBytes);
        return true;
    }

    private Optional<PlayerDevices.DeviceEntry> resolveDevice(PlayerDevices devices, String idOrPrefix) {
        PlayerDevices.DeviceEntry found = null;
        for (PlayerDevices.DeviceEntry entry : devices.getDevices()) {
            if (entry.getDeviceId() != null && entry.getDeviceId().startsWith(idOrPrefix)) {
                if (found != null) {
                    return Optional.empty();
                }
                found = entry;
            }
        }
        return Optional.ofNullable(found);
    }

    private record PendingOperation(
            String requestId, UUID playerId, String playerName, RecoveryOperation operation,
            String targetDeviceId, String label, byte[] nonce, long issuedAt, long authRevision
    ) {
        private boolean isExpired() {
            return System.currentTimeMillis() - issuedAt > TTL_MS;
        }

        private byte[] transcript(String serverId, byte[] newRecoveryPublicKey) {
            return CryptoV2.recoveryOperationTranscript(
                    requestId, nonce, serverId, playerName, operation.name(),
                    targetDeviceId, label, issuedAt, authRevision, newRecoveryPublicKey
            );
        }

        private RecoveryOperationRequest toPacket(String serverId) {
            return new RecoveryOperationRequest(
                    requestId, serverId, playerName, operation, targetDeviceId,
                    label, nonce, issuedAt, authRevision
            );
        }
    }
}
