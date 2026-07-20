/* This file is part of JarsAuth, licensed under GPLv3. */
package me.jissee.jarsauth.packet;

import me.jissee.jarsauth.client_auth.ClientCredentialStore;
import me.jissee.jarsauth.client_auth.CryptoV2;
import me.jissee.jarsauth.client_auth.RecoveryOperation;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkEvent;

import java.security.KeyPair;
import java.util.Optional;
import java.util.function.Supplier;

public final class RecoveryOperationRequest {
    private final String requestId;
    private final String serverId;
    private final String playerName;
    private final RecoveryOperation operation;
    private final String targetDeviceId;
    private final String label;
    private final byte[] nonce;
    private final long issuedAt;
    private final long authRevision;

    public RecoveryOperationRequest(String requestId, String serverId, String playerName,
                                    RecoveryOperation operation, String targetDeviceId, String label,
                                    byte[] nonce, long issuedAt, long authRevision) {
        this.requestId = requestId;
        this.serverId = serverId;
        this.playerName = playerName;
        this.operation = operation;
        this.targetDeviceId = targetDeviceId;
        this.label = label;
        this.nonce = nonce.clone();
        this.issuedAt = issuedAt;
        this.authRevision = authRevision;
    }

    public static void encode(RecoveryOperationRequest message, FriendlyByteBuf buf) {
        buf.writeUtf(message.requestId, 64);
        buf.writeUtf(message.serverId, 256);
        buf.writeUtf(message.playerName, 64);
        buf.writeByte(message.operation.ordinal());
        buf.writeUtf(message.targetDeviceId, 128);
        buf.writeUtf(message.label, 64);
        buf.writeByteArray(message.nonce);
        buf.writeLong(message.issuedAt);
        buf.writeLong(message.authRevision);
    }

    public static RecoveryOperationRequest decode(FriendlyByteBuf buf) {
        String requestId = buf.readUtf(64);
        String serverId = buf.readUtf(256);
        String playerName = buf.readUtf(64);
        int ordinal = buf.readUnsignedByte();
        if (ordinal >= RecoveryOperation.values().length) throw new IllegalArgumentException("Bad recovery operation");
        return new RecoveryOperationRequest(
                requestId, serverId, playerName, RecoveryOperation.values()[ordinal],
                buf.readUtf(128), buf.readUtf(64), buf.readByteArray(64), buf.readLong(), buf.readLong()
        );
    }

    public static void handle(RecoveryOperationRequest message, Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        context.enqueueWork(() -> {
            byte[] signature = new byte[0];
            byte[] newRecoveryPublicKey = new byte[0];
            byte[] newRecoverySignature = new byte[0];
            try {
                ClientCredentialStore store = ClientLoginAuth.getStore();
                Optional<KeyPair> recovery = store.loadRecoveryOrImport(message.serverId, message.playerName);
                if (recovery.isPresent()) {
                    KeyPair replacement = null;
                    if (message.operation == RecoveryOperation.ROTATE_RECOVERY) {
                        replacement = store.createReplacementRecovery(message.serverId, message.playerName);
                        newRecoveryPublicKey = replacement.getPublic().getEncoded();
                    }
                    byte[] transcript = CryptoV2.recoveryOperationTranscript(
                            message.requestId, message.nonce, message.serverId, message.playerName,
                            message.operation.name(), message.targetDeviceId, message.label,
                            message.issuedAt, message.authRevision, newRecoveryPublicKey
                    );
                    signature = CryptoV2.sign(recovery.get().getPrivate(), transcript);
                    if (replacement != null) {
                        newRecoverySignature = CryptoV2.sign(replacement.getPrivate(), transcript);
                    }
                }
            } catch (Exception ignored) {
            }
            PacketHandler.sendToServer(new RecoveryOperationResponse(
                    message.requestId, signature, newRecoveryPublicKey, newRecoverySignature
            ));
        });
        context.setPacketHandled(true);
    }
}
