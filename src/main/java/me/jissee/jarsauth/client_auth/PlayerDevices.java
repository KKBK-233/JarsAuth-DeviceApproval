/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.event.EventHandler;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.concurrent.ConcurrentHashMap;

/** 服务端持久化的账户与公钥设备记录。 */
public class PlayerDevices {
    public static final int CURRENT_SCHEMA_VERSION = 2;

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final String FOLDER_NAME = "device-files";
    private static final ConcurrentHashMap<String, Object> ACCOUNT_LOCKS = new ConcurrentHashMap<>();

    private int schemaVersion;
    private String playerName;
    private UUID accountId;
    private String recoveryPublicKey;
    private long authRevision;
    private ArrayList<DeviceEntry> devices;

    public PlayerDevices(String playerName, ArrayList<DeviceEntry> devices) {
        this.playerName = Objects.requireNonNull(playerName, "playerName");
        this.devices = devices == null ? new ArrayList<>() : devices;
        this.schemaVersion = CURRENT_SCHEMA_VERSION;
        this.accountId = UUID.randomUUID();
        this.authRevision = 1L;
        normalize();
    }

    public static PlayerDevices create(String playerName) {
        return new PlayerDevices(playerName, new ArrayList<>());
    }

    /** Serializes load-verify-mutate-save transactions across account instances. */
    public static Object accountLock(String playerName) {
        return ACCOUNT_LOCKS.computeIfAbsent(playerName.toLowerCase(Locale.ROOT), ignored -> new Object());
    }

    public static Optional<PlayerDevices> load(String playerName) {
        Path file = resolveFile(playerName).toPath();
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        return Optional.of(read(file, playerName));
    }

    /** Loads every account file in deterministic player-name order. */
    public static List<PlayerDevices> loadAll() {
        Path folder = resolveFolder();
        try (Stream<Path> files = Files.list(folder)) {
            ArrayList<PlayerDevices> result = new ArrayList<>();
            files.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".json"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString(), String.CASE_INSENSITIVE_ORDER))
                    .forEach(path -> {
                        String fileName = path.getFileName().toString();
                        try {
                            result.add(read(path, fileName.substring(0, fileName.length() - 5)));
                        } catch (RuntimeException e) {
                            LOGGER.error("Skipping corrupt JarsAuth device record {}", path, e);
                        }
                    });
            return result;
        } catch (IOException e) {
            throw new RuntimeException("Could not enumerate JarsAuth device records", e);
        }
    }

    private static PlayerDevices read(Path file, String fallbackPlayerName) {
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            PlayerDevices loaded = GSON.fromJson(reader, PlayerDevices.class);
            if (loaded == null) {
                throw new IOException("Empty account file: " + file);
            }
            if (loaded.playerName == null || loaded.playerName.isBlank()) {
                loaded.playerName = fallbackPlayerName;
            }
            loaded.normalize();
            return loaded;
        } catch (IOException | RuntimeException e) {
            throw new RuntimeException("Could not load JarsAuth device record " + file, e);
        }
    }

    /** Writes through a sibling temporary file and atomically replaces the old record. */
    public synchronized void save() {
        normalize();
        Path file = resolveFile(playerName).toPath();
        Path temporary = file.resolveSibling(file.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                writer.write(GSON.toJson(this));
            }
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // The original account file was never replaced; a stale temp is harmless.
            }
            throw new RuntimeException("Could not save JarsAuth device record " + file, e);
        }
    }

    /** Registers a public-key device, or refreshes the matching existing record. */
    public synchronized DeviceEntry registerV2Device(String deviceId, String publicKey, String label, boolean approved) {
        requireText(deviceId, "deviceId");
        requireText(publicKey, "publicKey");
        DeviceEntry existing = findByDeviceId(deviceId).orElse(null);
        if (existing != null) {
            if (existing.publicKey != null && !existing.publicKey.equals(publicKey)) {
                throw new IllegalArgumentException("deviceId is already registered with a different public key");
            }
            existing.publicKey = publicKey;
            existing.setLabel(label);
            existing.touch();
            boolean wasApproved = existing.isApproved();
            if (approved) {
                existing.approve();
            }
            if (approved && !wasApproved) {
                bumpAuthRevision();
            }
            return existing;
        }
        if (findByPublicKey(publicKey).isPresent()) {
            throw new IllegalArgumentException("public key is already registered under a different deviceId");
        }
        DeviceEntry entry = DeviceEntry.createV2(deviceId, publicKey, label,
                approved ? DeviceStatus.APPROVED : DeviceStatus.PENDING);
        devices.add(entry);
        bumpAuthRevision();
        return entry;
    }

    /** Binary-key convenience API used by the login protocol. Keys are stored as Base64 in JSON. */
    public synchronized DeviceEntry registerV2Device(byte[] publicKey, String label, boolean approved) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length == 0) {
            throw new IllegalArgumentException("publicKey must not be empty");
        }
        String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey);
        return registerV2Device(deviceId(publicKey), encodedPublicKey, label, approved);
    }

    public Optional<DeviceEntry> findByDeviceId(String deviceId) {
        if (deviceId == null) {
            return Optional.empty();
        }
        return devices.stream().filter(device -> deviceId.equals(device.deviceId)).findFirst();
    }

    public Optional<DeviceEntry> findByPublicKey(String publicKey) {
        if (publicKey == null) {
            return Optional.empty();
        }
        return devices.stream().filter(device -> publicKey.equals(device.publicKey)).findFirst();
    }

    public Optional<DeviceEntry> findByRequestId(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        return devices.stream().filter(device -> requestId.equals(device.getRequestId())).findFirst();
    }

    public synchronized boolean revokeDevice(String deviceId) {
        DeviceEntry entry = findByDeviceId(deviceId).orElse(null);
        if (entry == null || entry.getStatus() == DeviceStatus.REVOKED) {
            return false;
        }
        entry.revoke();
        bumpAuthRevision();
        return true;
    }

    public synchronized boolean renameDevice(String deviceId, String label) {
        DeviceEntry entry = findByDeviceId(deviceId).orElse(null);
        if (entry == null || label == null || label.isBlank()) {
            return false;
        }
        String normalized = label.replaceAll("[\\r\\n\\t]", " ").trim();
        if (normalized.length() > 48) {
            normalized = normalized.substring(0, 48);
        }
        entry.setLabel(normalized);
        bumpAuthRevision();
        return true;
    }

    /** Removes a pending/revoked request after the user or administrator rejects it. */
    public synchronized boolean removeRejectedDevice(String requestId) {
        DeviceEntry entry = findByRequestId(requestId).orElse(null);
        if (entry == null || entry.getStatus() == DeviceStatus.APPROVED) {
            return false;
        }
        boolean removed = devices.remove(entry);
        if (removed) {
            bumpAuthRevision();
        }
        return removed;
    }

    public synchronized boolean removeDevice(DeviceEntry entry) {
        if (entry == null || !devices.remove(entry)) {
            return false;
        }
        bumpAuthRevision();
        return true;
    }

    /** Updates in-memory audit data only; the caller's periodic flush policy decides when to save. */
    public synchronized void markSeen(DeviceEntry entry) {
        if (entry != null && devices.contains(entry)) {
            entry.touch();
        }
    }

    public int countApprovedDevices() {
        int count = 0;
        for (DeviceEntry device : devices) {
            if (device.isApproved()) {
                count++;
            }
        }
        return count;
    }

    public List<DeviceEntry> getDevices() {
        return devices;
    }

    public String getPlayerName() {
        return playerName;
    }

    public UUID getAccountId() {
        return accountId;
    }

    public String getRecoveryPublicKey() {
        return recoveryPublicKey;
    }

    public byte[] getRecoveryPublicKeyBytes() {
        return decodeBase64(recoveryPublicKey);
    }

    public long getAuthRevision() {
        return authRevision;
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    /** Migration is irreversible: a registered recovery key permanently marks v2. */
    public boolean isV2() {
        return recoveryPublicKey != null && !recoveryPublicKey.isBlank();
    }

    public synchronized void enableV2(byte[] recoveryPublicKey) {
        Objects.requireNonNull(recoveryPublicKey, "recoveryPublicKey");
        if (recoveryPublicKey.length == 0) {
            throw new IllegalArgumentException("recoveryPublicKey must not be empty");
        }
        setRecoveryPublicKey(Base64.getEncoder().encodeToString(recoveryPublicKey));
    }

    /** Replacing or initially setting the recovery key invalidates earlier signed mutations. */
    public synchronized void setRecoveryPublicKey(String recoveryPublicKey) {
        requireText(recoveryPublicKey, "recoveryPublicKey");
        if (!recoveryPublicKey.equals(this.recoveryPublicKey)) {
            this.recoveryPublicKey = recoveryPublicKey;
            bumpAuthRevision();
        }
    }

    public synchronized void clearRecoveryPublicKey() {
        if (recoveryPublicKey != null) {
            recoveryPublicKey = null;
            bumpAuthRevision();
        }
    }

    private void normalize() {
        schemaVersion = CURRENT_SCHEMA_VERSION;
        if (accountId == null) {
            accountId = UUID.randomUUID();
        }
        if (authRevision < 1L) {
            authRevision = 1L;
        }
        if (devices == null) {
            devices = new ArrayList<>();
        }
        for (DeviceEntry device : devices) {
            if (device != null) {
                device.normalize();
            }
        }
        devices.removeIf(Objects::isNull);
    }

    private void bumpAuthRevision() {
        authRevision = authRevision == Long.MAX_VALUE ? 1L : authRevision + 1L;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static String deviceId(byte[] publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey);
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                result.append(Character.forDigit((value >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(value & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static byte[] decodeBase64(String value) {
        return value == null || value.isBlank() ? null : Base64.getDecoder().decode(value);
    }

    private static Path resolveFolder() {
        Path folder = Path.of(EventHandler.getServerSaveDir(), FOLDER_NAME);
        try {
            Files.createDirectories(folder);
        } catch (IOException e) {
            throw new RuntimeException("Could not create JarsAuth device directory " + folder, e);
        }
        return folder;
    }

    private static File resolveFile(String playerName) {
        return resolveFolder().resolve(playerName + ".json").toFile();
    }

    public enum DeviceStatus {
        APPROVED,
        PENDING,
        REVOKED
    }

    public static class DeviceEntry {
        private String deviceId;
        private String publicKey;
        private DeviceStatus status;
        private String label;
        private long createdAt;
        private long approvedAt;
        private long lastSeenAt;
        private long revokedAt;
        private String requestId;

        public DeviceEntry() {
        }

        public static DeviceEntry createV2(String deviceId, String publicKey, String label, DeviceStatus status) {
            requireText(deviceId, "deviceId");
            requireText(publicKey, "publicKey");
            long now = System.currentTimeMillis();
            DeviceEntry entry = new DeviceEntry();
            entry.deviceId = deviceId;
            entry.publicKey = publicKey;
            entry.label = label;
            entry.status = status == null ? DeviceStatus.PENDING : status;
            entry.createdAt = now;
            entry.approvedAt = entry.status == DeviceStatus.APPROVED ? now : 0;
            entry.lastSeenAt = now;
            entry.requestId = newRequestId();
            return entry;
        }

        private void normalize() {
            if (status == null) {
                status = DeviceStatus.PENDING;
            }
            long now = System.currentTimeMillis();
            if (createdAt <= 0L) {
                createdAt = now;
            }
            if (lastSeenAt <= 0L) {
                lastSeenAt = createdAt;
            }
            if (status == DeviceStatus.APPROVED && approvedAt <= 0L) {
                approvedAt = createdAt;
            }
            if (requestId == null || requestId.isBlank()) {
                requestId = newRequestId();
            }
        }

        public boolean isApproved() {
            return getStatus() == DeviceStatus.APPROVED;
        }

        public void approve() {
            this.status = DeviceStatus.APPROVED;
            this.approvedAt = System.currentTimeMillis();
            this.revokedAt = 0L;
            touch();
        }

        public void revoke() {
            this.status = DeviceStatus.REVOKED;
            this.revokedAt = System.currentTimeMillis();
            touch();
        }

        public void markPending() {
            this.status = DeviceStatus.PENDING;
            this.approvedAt = 0L;
            this.revokedAt = 0L;
            this.requestId = newRequestId();
            touch();
        }

        public void touch() {
            this.lastSeenAt = System.currentTimeMillis();
        }

        public String getDeviceId() {
            return deviceId;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public byte[] getPublicKeyBytes() {
            return decodeBase64(publicKey);
        }

        public boolean isPending() {
            return getStatus() == DeviceStatus.PENDING;
        }

        public DeviceStatus getStatus() {
            if (status == null) {
                status = DeviceStatus.PENDING;
            }
            return status;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public long getCreatedAt() {
            return createdAt;
        }

        public long getApprovedAt() {
            return approvedAt;
        }

        public long getLastSeenAt() {
            return lastSeenAt;
        }

        public long getRevokedAt() {
            return revokedAt;
        }

        public String getRequestId() {
            return requestId;
        }

        private static String newRequestId() {
            return UUID.randomUUID().toString().substring(0, 8).toLowerCase(Locale.ROOT);
        }
    }
}
