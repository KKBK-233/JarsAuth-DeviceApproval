/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.client_auth;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.packet.AuthLoginResponse;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import org.slf4j.Logger;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Holds the short-lived state used by Forge's pre-PLAY login negotiation.
 * No ServerPlayer exists while this class authenticates the connection.
 */
public final class LoginAuthManager {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final long CHALLENGE_TTL_MS = Duration.ofSeconds(25).toMillis();
    private static final LoginAuthManager INSTANCE = new LoginAuthManager();

    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final Map<Connection, LoginSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, AcceptedLogin> acceptedLogins = new ConcurrentHashMap<>();
    private final ScheduledExecutorService timeoutExecutor;
    private final ThreadPoolExecutor authExecutor;

    private LoginAuthManager() {
        ThreadFactory timeoutFactory = runnable -> {
            Thread thread = new Thread(runnable, "JarsAuth-LoginTimeout");
            thread.setDaemon(true);
            return thread;
        };
        ThreadFactory authFactory = runnable -> {
            Thread thread = new Thread(runnable, "JarsAuth-LoginWorker");
            thread.setDaemon(true);
            return thread;
        };
        timeoutExecutor = Executors.newSingleThreadScheduledExecutor(timeoutFactory);
        authExecutor = new ThreadPoolExecutor(
                1, 2, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(128), authFactory, new ThreadPoolExecutor.AbortPolicy()
        );
    }

    public static LoginAuthManager getInstance() {
        return INSTANCE;
    }

    public void rememberChallenge(String sessionId, byte[] nonce, String serverId, long issuedAt) {
        challenges.put(sessionId, new Challenge(nonce.clone(), serverId, issuedAt));
        cleanupChallenges();
    }

    public void begin(PlayerNegotiationEvent event) {
        if (Settings.getClientAuthSetting() == null || !Settings.getClientAuthSetting().isEnabled()) {
            return;
        }
        CompletableFuture<Void> gate = new CompletableFuture<>();
        LoginSession session = new LoginSession(event.getConnection(), event.getProfile(), gate);
        sessions.put(event.getConnection(), session);
        event.enqueueWork(gate);
        timeoutExecutor.schedule(() -> timeout(event.getConnection(), session), CHALLENGE_TTL_MS, TimeUnit.MILLISECONDS);
    }

    public void handleResponse(AuthLoginResponse response, Connection connection) {
        LoginSession login = sessions.get(connection);
        if (login == null || !login.processing.compareAndSet(false, true)) {
            return;
        }
        try {
            authExecutor.execute(() -> handleResponseNow(response, connection));
        } catch (RejectedExecutionException e) {
            fail(connection, login, "JarsAuth authentication queue is busy; retry shortly");
        }
    }

    private void handleResponseNow(AuthLoginResponse response, Connection connection) {
        LoginSession login = sessions.get(connection);
        if (login == null) {
            return;
        }
        synchronized (login) {
            if (login.finished.get()) {
                return;
            }
        if (!response.isEnabled()) {
            fail(connection, login, "JarsAuth is enabled on the server but disabled in the login response");
            return;
        }

        Challenge challenge = challenges.remove(response.getSessionId());
        if (challenge == null || challenge.isExpired()) {
            fail(connection, login, "JarsAuth challenge expired");
            return;
        }

        String playerName = login.profile.getName();
        if (!playerName.equalsIgnoreCase(response.getPlayerName())) {
            fail(connection, login, "JarsAuth player binding mismatch");
            return;
        }

        try {
            byte[] transcript = CryptoV2.loginTranscript(
                    response.getSessionId(), challenge.nonce, challenge.serverId, playerName,
                    response.getMode(), response.getDeviceLabel(), response.getDevicePublicKey(), response.getRecoveryPublicKey()
            );
            PublicKey suppliedDeviceKey = CryptoV2.decodePublicKey(response.getDevicePublicKey());
            if (!CryptoV2.verify(suppliedDeviceKey, transcript, response.getDeviceSignature())) {
                fail(connection, login, "JarsAuth device proof is invalid");
                return;
            }

            synchronized (PlayerDevices.accountLock(playerName)) {
                PlayerDevices devices = PlayerDevices.load(playerName).orElse(PlayerDevices.create(playerName));
                switch (response.getMode()) {
                    case DEVICE -> authenticateDevice(connection, login, devices, response, transcript);
                    case RECOVERY -> authenticateRecovery(connection, login, devices, response, transcript);
                    case LEGACY_MIGRATION -> migrateLegacy(connection, login, devices, response, transcript);
                    case ENROLL -> enroll(connection, login, devices, response, transcript);
                }
            }
        } catch (Exception e) {
            LOGGER.warn("JarsAuth login failed for {}", playerName, e);
            fail(connection, login, "JarsAuth authentication failed");
        }
        }
    }

    private void authenticateDevice(Connection connection, LoginSession login, PlayerDevices devices,
                                    AuthLoginResponse response, byte[] transcript) throws Exception {
        String deviceId = CryptoV2.deviceId(response.getDevicePublicKey());
        Optional<PlayerDevices.DeviceEntry> entry = devices.findByDeviceId(deviceId);
        if (entry.isEmpty() || !entry.get().isApproved() || entry.get().getPublicKeyBytes() == null) {
            if (entry.isPresent() && entry.get().isPending()) {
                CAPendingList.getInstance().ensurePendingApproval(devices, entry.get());
                fail(connection, login, "This device is waiting for administrator approval");
            } else {
                fail(connection, login, "This device is not registered");
            }
            return;
        }
        if (!MessageDigest.isEqual(entry.get().getPublicKeyBytes(), response.getDevicePublicKey())) {
            fail(connection, login, "JarsAuth device key mismatch");
            return;
        }
        if (!CryptoV2.verify(CryptoV2.decodePublicKey(entry.get().getPublicKeyBytes()), transcript, response.getDeviceSignature())) {
            fail(connection, login, "JarsAuth device signature is invalid");
            return;
        }
        devices.markSeen(entry.get());
        succeed(login, devices, entry.get());
    }

    private void authenticateRecovery(Connection connection, LoginSession login, PlayerDevices devices,
                                      AuthLoginResponse response, byte[] transcript) throws Exception {
        if (!devices.isV2() || devices.getRecoveryPublicKeyBytes() == null) {
            fail(connection, login, "No recovery key is registered for this account");
            return;
        }
        if (!CryptoV2.verify(CryptoV2.decodePublicKey(devices.getRecoveryPublicKeyBytes()), transcript, response.getRecoverySignature())) {
            fail(connection, login, "JarsAuth recovery proof is invalid");
            return;
        }
        PlayerDevices.DeviceEntry entry = devices.registerV2Device(
                response.getDevicePublicKey(), response.getDeviceLabel(), true, null
        );
        devices.save();
        succeed(login, devices, entry);
    }

    private void migrateLegacy(Connection connection, LoginSession login, PlayerDevices devices,
                               AuthLoginResponse response, byte[] transcript) throws Exception {
        if (devices.isV2()) {
            String deviceId = CryptoV2.deviceId(response.getDevicePublicKey());
            Optional<PlayerDevices.DeviceEntry> migrated = devices.findByDeviceId(deviceId);
            if (migrated.isPresent() && migrated.get().isApproved()
                    && MessageDigest.isEqual(migrated.get().getPublicKeyBytes(), response.getDevicePublicKey())) {
                devices.markSeen(migrated.get());
                succeed(login, devices, migrated.get());
                return;
            }
            fail(connection, login, "Legacy authentication is disabled for this account");
            return;
        }
        if (response.getLegacySecret().length != 16 || response.getRecoveryPublicKey().length == 0) {
            fail(connection, login, "Legacy migration data is incomplete");
            return;
        }
        UUID rawDeviceId = Codec.bytesToUUID(response.getLegacySecret());
        UUID hashedDeviceId = PlayerDevices.hashDeviceId(rawDeviceId);
        Optional<PlayerDevices.DeviceEntry> legacy = devices.findByHashedDeviceId(hashedDeviceId);
        if (legacy.isEmpty() || !legacy.get().isApproved()) {
            fail(connection, login, "Legacy device credential is invalid");
            return;
        }
        if (!CryptoV2.verify(CryptoV2.decodePublicKey(response.getRecoveryPublicKey()), transcript, response.getRecoverySignature())) {
            fail(connection, login, "Recovery-key proof is invalid");
            return;
        }
        devices.enableV2(response.getRecoveryPublicKey());
        PlayerDevices.DeviceEntry entry = devices.registerV2Device(
                response.getDevicePublicKey(), response.getDeviceLabel(), true, null
        );
        devices.save();
        succeed(login, devices, entry);
    }

    private void enroll(Connection connection, LoginSession login, PlayerDevices devices,
                        AuthLoginResponse response, byte[] transcript) throws Exception {
        if (!devices.isV2() && devices.countApprovedDevices() == 0) {
            if (response.getRecoveryPublicKey().length == 0
                    || !CryptoV2.verify(CryptoV2.decodePublicKey(response.getRecoveryPublicKey()), transcript, response.getRecoverySignature())) {
                fail(connection, login, "A recovery-key proof is required for first enrollment");
                return;
            }
            devices.enableV2(response.getRecoveryPublicKey());
            PlayerDevices.DeviceEntry entry = devices.registerV2Device(
                    response.getDevicePublicKey(), response.getDeviceLabel(), true, null
            );
            devices.save();
            succeed(login, devices, entry);
            return;
        }

        byte[] candidateRecovery = devices.isV2() ? null : response.getRecoveryPublicKey();
        PlayerDevices.DeviceEntry entry = devices.registerV2Device(
                response.getDevicePublicKey(), response.getDeviceLabel(), false, candidateRecovery
        );
        if (entry.isApproved()) {
            devices.markSeen(entry);
            succeed(login, devices, entry);
            return;
        }
        devices.save();
        CAPendingList.getInstance().ensurePendingApproval(devices, entry);
        fail(connection, login, "This device is waiting for administrator approval");
    }

    private void succeed(LoginSession login, PlayerDevices devices, PlayerDevices.DeviceEntry entry) {
        login.accountId = devices.getAccountId();
        login.deviceId = entry.getDeviceId();
        login.recoveryPublicKey = devices.getRecoveryPublicKeyBytes();
        acceptedLogins.put(login.profile.getName(), new AcceptedLogin(
                devices.getAccountId(), entry.getDeviceId(), devices.getRecoveryPublicKeyBytes()
        ));
        if (login.finished.compareAndSet(false, true)) {
            sessions.remove(login.connection, login);
            login.gate.complete(null);
        }
    }

    public Optional<AcceptedLogin> consumeAccepted(String playerName) {
        return Optional.ofNullable(acceptedLogins.remove(playerName));
    }

    private void fail(Connection connection, LoginSession login, String reason) {
        if (login.finished.compareAndSet(false, true)) {
            sessions.remove(connection, login);
            LOGGER.info("Rejected pre-login connection for {}: {}", login.profile.getName(), reason);
            connection.disconnect(Component.literal(reason));
            login.gate.complete(null);
        }
    }

    private void timeout(Connection connection, LoginSession expected) {
        synchronized (expected) {
            if (sessions.get(connection) == expected) {
                fail(connection, expected, "JarsAuth login timed out");
            }
        }
    }

    private void cleanupChallenges() {
        challenges.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    private record Challenge(byte[] nonce, String serverId, long issuedAt) {
        private boolean isExpired() {
            return System.currentTimeMillis() - issuedAt > CHALLENGE_TTL_MS;
        }
    }

    public record AcceptedLogin(UUID accountId, String deviceId, byte[] recoveryPublicKey) {
        public AcceptedLogin {
            recoveryPublicKey = recoveryPublicKey == null ? new byte[0] : recoveryPublicKey.clone();
        }

        @Override
        public byte[] recoveryPublicKey() {
            return recoveryPublicKey.clone();
        }
    }

    private static final class LoginSession {
        private final Connection connection;
        private final GameProfile profile;
        private final CompletableFuture<Void> gate;
        private final AtomicBoolean processing = new AtomicBoolean();
        private final AtomicBoolean finished = new AtomicBoolean();
        private UUID accountId;
        private String deviceId;
        private byte[] recoveryPublicKey;

        private LoginSession(Connection connection, GameProfile profile, CompletableFuture<Void> gate) {
            this.connection = connection;
            this.profile = profile;
            this.gate = gate;
        }
    }
}
