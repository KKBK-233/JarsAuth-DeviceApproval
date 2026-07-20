/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.packet;

import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.client_auth.AuthMode;
import me.jissee.jarsauth.client_auth.ClientCredentialStore;
import me.jissee.jarsauth.client_auth.CryptoV2;
import net.minecraft.client.Minecraft;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.util.Optional;

/** Client-only construction of the pre-login authentication response. */
final class ClientLoginAuth {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static volatile ClientCredentialStore store;

    private ClientLoginAuth() {
    }

    static AuthLoginResponse createResponse(AuthLoginQuery query) {
        if (!query.isEnabled()) {
            return emptyResponse(query);
        }
        try {
            Minecraft minecraft = Minecraft.getInstance();
            String playerName = minecraft.getUser().getName();
            ClientCredentialStore credentials = getStore();
            ClientCredentialStore.Credential device = credentials.loadOrCreateDevice(query.getServerId(), playerName);

            AuthMode mode;
            KeyPair recovery = null;
            if (device.accepted()) {
                mode = AuthMode.DEVICE;
            } else {
                Optional<KeyPair> importedRecovery = credentials.loadRecoveryOrImport(query.getServerId(), playerName);
                if (importedRecovery.isPresent()) {
                    mode = AuthMode.RECOVERY;
                    recovery = importedRecovery.get();
                } else if (!device.isNew()) {
                    // 已提交过登记申请的设备继续使用设备证明，等待管理员批准。
                    mode = AuthMode.DEVICE;
                } else {
                    recovery = credentials.createCandidateRecovery(query.getServerId(), playerName);
                    mode = AuthMode.ENROLL;
                }
            }

            byte[] devicePublic = device.keyPair().getPublic().getEncoded();
            byte[] recoveryPublic = recovery == null ? new byte[0] : recovery.getPublic().getEncoded();
            byte[] transcript = CryptoV2.loginTranscript(
                    query.getSessionId(), query.getNonce(), query.getServerId(), playerName,
                    mode, device.label(), devicePublic, recoveryPublic
            );
            byte[] deviceSignature = CryptoV2.sign(device.keyPair().getPrivate(), transcript);
            byte[] recoverySignature = recovery == null
                    ? new byte[0]
                    : CryptoV2.sign(recovery.getPrivate(), transcript);
            return new AuthLoginResponse(
                    true, query.getSessionId(), mode, playerName, device.label(),
                    devicePublic, deviceSignature, recoveryPublic, recoverySignature
            );
        } catch (Exception e) {
            LOGGER.error("Could not prepare JarsAuth pre-login proof", e);
            return emptyResponse(query);
        }
    }

    static ClientCredentialStore getStore() {
        ClientCredentialStore current = store;
        if (current == null) {
            synchronized (ClientLoginAuth.class) {
                current = store;
                if (current == null) {
                    current = new ClientCredentialStore();
                    store = current;
                }
            }
        }
        return current;
    }

    private static AuthLoginResponse emptyResponse(AuthLoginQuery query) {
        String playerName;
        try {
            playerName = Minecraft.getInstance().getUser().getName();
        } catch (Exception ignored) {
            playerName = "unknown";
        }
        return new AuthLoginResponse(
                false, query.getSessionId(), AuthMode.ENROLL, playerName, "unavailable",
                new byte[0], new byte[0], new byte[0], new byte[0]
        );
    }
}
