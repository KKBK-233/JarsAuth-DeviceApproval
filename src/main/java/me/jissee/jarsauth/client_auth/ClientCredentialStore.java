/*
 * This file is part of JarsAuth, licensed under the GNU GPL v3.0.
 */
package me.jissee.jarsauth.client_auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.sun.jna.platform.win32.Crypt32Util;

import java.io.IOException;
import java.io.Reader;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Persistent client credentials shared by all launcher instances for the same
 * operating-system account. Device and recovery private keys are always
 * encrypted with the installation key before they reach disk.
 */
public final class ClientCredentialStore {
    private static final int FORMAT_VERSION = 2;
    private static final String RECOVERY_PREFIX_V1 = "JA2-R1";
    private static final String RECOVERY_PREFIX_V2 = "JA2-R2";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final Object JVM_FILE_LOCK = new Object();
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private final Path root;
    private final Path credentialsDirectory;
    private final Path legacyMinecraftDirectory;
    private final boolean windows;
    private final byte[] machineBindingMaterial;
    private volatile byte[] cachedInstallKey;

    public ClientCredentialStore() {
        this(defaultRootDirectory(), null);
    }

    public ClientCredentialStore(Path legacyMinecraftDirectory) {
        this(defaultRootDirectory(), legacyMinecraftDirectory);
    }

    public ClientCredentialStore(Path root, Path legacyMinecraftDirectory) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.credentialsDirectory = this.root.resolve("credentials");
        this.legacyMinecraftDirectory = legacyMinecraftDirectory == null
                ? null : legacyMinecraftDirectory.toAbsolutePath().normalize();
        this.windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        this.machineBindingMaterial = calculateMachineBindingMaterial();
    }

    /** Load the shared device, or atomically replace an unusable/copied one. */
    public Credential loadOrCreateDevice(String serverId, String playerName) {
        validateScope(serverId, playerName);
        return locked(() -> loadOrCreateDeviceUnlocked(serverId, playerName));
    }

    /** Returns only an accepted/imported recovery key, never a pending candidate. */
    public Optional<KeyPair> loadRecoveryForUse(String serverId, String playerName) {
        validateScope(serverId, playerName);
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            StoredCredential stored = readStored(scopePath(serverId, playerName));
            if (stored == null || stored.recovery == null || !bindingMatches(stored, installKey)) {
                return Optional.empty();
            }
            return Optional.of(decryptKeyPair(stored.recovery, installKey,
                    recoveryAad(serverId, playerName, stored.recovery.publicKey)));
        });
    }

    /**
     * Loads the protected recovery key, or imports a one-line code placed in
     * {@code recovery-import.txt}. The consumed import file is archived.
     */
    public Optional<KeyPair> loadRecoveryOrImport(String serverId, String playerName) {
        Optional<KeyPair> accepted = loadRecoveryForUse(serverId, playerName);
        if (accepted.isPresent()) {
            return accepted;
        }
        Optional<KeyPair> staged = loadPendingRecovery(serverId, playerName);
        if (staged.isPresent()) {
            return staged;
        }

        Path importFile = root.resolve("recovery-import").resolve(recoveryFileName(serverId, playerName));
        if (!Files.isRegularFile(importFile)) {
            importFile = root.resolve("recovery-import.txt");
        }
        if (!Files.isRegularFile(importFile)) {
            return Optional.empty();
        }
        try {
            String code = Files.readAllLines(importFile, StandardCharsets.UTF_8).stream()
                    .map(String::strip)
                    .filter(line -> line.startsWith("JA2-R"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Recovery file has no key"));
            KeyPair imported = stageImportedRecovery(serverId, playerName, code);
            Path used = importFile.resolveSibling("recovery-import.used-" + Instant.now().toEpochMilli() + ".txt");
            Files.move(importFile, used, StandardCopyOption.REPLACE_EXISTING);
            restrictFile(used);
            return Optional.of(imported);
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private Optional<KeyPair> loadPendingRecovery(String serverId, String playerName) {
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            StoredCredential stored = readStored(scopePath(serverId, playerName));
            if (stored == null || stored.pendingRecovery == null || !stored.pendingRecoveryImported
                    || !bindingMatches(stored, installKey)) {
                return Optional.empty();
            }
            return Optional.of(decryptKeyPair(stored.pendingRecovery, installKey,
                    recoveryAad(serverId, playerName, stored.pendingRecovery.publicKey)));
        });
    }

    /** Create once and persist a pending recovery key until the server accepts it. */
    public KeyPair createCandidateRecovery(String serverId, String playerName) {
        validateScope(serverId, playerName);
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            loadOrCreateDeviceUnlocked(serverId, playerName);
            Path path = scopePath(serverId, playerName);
            StoredCredential stored = requireStored(path);
            if (stored.pendingRecovery != null) {
                return decryptKeyPair(stored.pendingRecovery, installKey,
                        recoveryAad(serverId, playerName, stored.pendingRecovery.publicKey));
            }
            KeyPair candidate = CryptoV2.generateEd25519KeyPair();
            stored.pendingRecovery = encryptKeyPair(candidate, installKey,
                    recoveryAad(serverId, playerName, candidate.getPublic().getEncoded()));
            stored.pendingRecoveryImported = false;
            stored.updatedAt = System.currentTimeMillis();
            writeStored(path, stored);
            return candidate;
        });
    }

    /** Creates a fresh staged recovery key for an authenticated rotation. */
    public KeyPair createReplacementRecovery(String serverId, String playerName) {
        validateScope(serverId, playerName);
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            loadOrCreateDeviceUnlocked(serverId, playerName);
            Path path = scopePath(serverId, playerName);
            StoredCredential stored = requireStored(path);
            KeyPair replacement = CryptoV2.generateEd25519KeyPair();
            stored.pendingRecovery = encryptKeyPair(replacement, installKey,
                    recoveryAad(serverId, playerName, replacement.getPublic().getEncoded()));
            stored.pendingRecoveryImported = false;
            stored.updatedAt = System.currentTimeMillis();
            writeStored(path, stored);
            return replacement;
        });
    }

    /**
     * Promote the matching candidate after server acknowledgement. The returned
     * recovery code is the one-time value that should be shown/saved offline.
     */
    public Optional<String> onServerAccepted(
            String serverId, String playerName, byte[] acceptedRecoveryPublicKey) {
        validateScope(serverId, playerName);
        Objects.requireNonNull(acceptedRecoveryPublicKey, "acceptedRecoveryPublicKey");
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            Path path = scopePath(serverId, playerName);
            StoredCredential stored = readStored(path);
            if (stored == null || !bindingMatches(stored, installKey)) return Optional.empty();

            EncryptedKey pending = stored.pendingRecovery;
            if (pending == null || !CryptoV2.constantTimeEquals(
                    CryptoV2.base64Decode(pending.publicKey), acceptedRecoveryPublicKey)) {
                return Optional.empty();
            }
            KeyPair pair = decryptKeyPair(pending, installKey,
                    recoveryAad(serverId, playerName, acceptedRecoveryPublicKey));
            stored.recovery = pending;
            stored.pendingRecovery = null;
            stored.pendingRecoveryImported = false;
            stored.updatedAt = System.currentTimeMillis();
            writeStored(path, stored);
            return Optional.of(exportRecovery(serverId, playerName, pair));
        });
    }

    public Optional<String> onServerAccepted(
            String serverId, String playerName, PublicKey acceptedRecoveryPublicKey) {
        return onServerAccepted(serverId, playerName, acceptedRecoveryPublicKey.getEncoded());
    }

    /** Import a recovery code into protected shared storage for the next login. */
    public KeyPair stageImportedRecovery(String serverId, String playerName, String recoveryCode) {
        validateScope(serverId, playerName);
        KeyPair imported = importScopedRecovery(serverId, playerName, recoveryCode);
        return locked(() -> {
            byte[] installKey = loadOrCreateInstallKey();
            loadOrCreateDeviceUnlocked(serverId, playerName);
            Path path = scopePath(serverId, playerName);
            StoredCredential stored = requireStored(path);
            stored.pendingRecovery = encryptKeyPair(imported, installKey,
                    recoveryAad(serverId, playerName, imported.getPublic().getEncoded()));
            stored.pendingRecoveryImported = true;
            stored.updatedAt = System.currentTimeMillis();
            writeStored(path, stored);
            return imported;
        });
    }

    /** Export is explicit because this string contains the recovery private key. */
    public static String exportRecovery(KeyPair recovery) {
        byte[] privateKey = recovery.getPrivate().getEncoded();
        byte[] publicKey = recovery.getPublic().getEncoded();
        byte[] check = CryptoV2.sha256(privateKey, publicKey);
        byte[] shortCheck = java.util.Arrays.copyOf(check, 8);
        return RECOVERY_PREFIX_V1 + "." + CryptoV2.base64Url(privateKey) + "."
                + CryptoV2.base64Url(publicKey) + "." + CryptoV2.base64Url(shortCheck);
    }

    public static String exportRecovery(String serverId, String playerName, KeyPair recovery) {
        byte[] privateKey = recovery.getPrivate().getEncoded();
        byte[] publicKey = recovery.getPublic().getEncoded();
        byte[] scope = recoveryScope(serverId, playerName);
        byte[] check = java.util.Arrays.copyOf(CryptoV2.sha256(scope, privateKey, publicKey), 8);
        return RECOVERY_PREFIX_V2 + "." + CryptoV2.base64Url(scope) + "."
                + CryptoV2.base64Url(privateKey) + "." + CryptoV2.base64Url(publicKey)
                + "." + CryptoV2.base64Url(check);
    }

    public static KeyPair importRecovery(String recoveryCode) {
        Objects.requireNonNull(recoveryCode, "recoveryCode");
        String[] parts = recoveryCode.strip().split("\\.", -1);
        if (parts.length != 4 || !RECOVERY_PREFIX_V1.equals(parts[0])) {
            throw new IllegalArgumentException("Unsupported JarsAuth recovery code");
        }
        byte[] privateBytes = CryptoV2.base64UrlDecode(parts[1]);
        byte[] publicBytes = CryptoV2.base64UrlDecode(parts[2]);
        byte[] expectedCheck = java.util.Arrays.copyOf(CryptoV2.sha256(privateBytes, publicBytes), 8);
        if (!CryptoV2.constantTimeEquals(expectedCheck, CryptoV2.base64UrlDecode(parts[3]))) {
            throw new IllegalArgumentException("Recovery code checksum is invalid");
        }
        KeyPair pair = new KeyPair(CryptoV2.decodePublicKey(publicBytes),
                CryptoV2.decodePrivateKey(privateBytes));
        verifyPair(pair);
        return pair;
    }

    public static KeyPair importScopedRecovery(String serverId, String playerName, String recoveryCode) {
        Objects.requireNonNull(recoveryCode, "recoveryCode");
        String[] parts = recoveryCode.strip().split("\\.", -1);
        if (parts.length != 5 || !RECOVERY_PREFIX_V2.equals(parts[0])) {
            throw new IllegalArgumentException("Unsupported JarsAuth recovery code");
        }
        byte[] scope = recoveryScope(serverId, playerName);
        if (!CryptoV2.constantTimeEquals(scope, CryptoV2.base64UrlDecode(parts[1]))) {
            throw new IllegalArgumentException("Recovery code belongs to another server or player");
        }
        byte[] privateBytes = CryptoV2.base64UrlDecode(parts[2]);
        byte[] publicBytes = CryptoV2.base64UrlDecode(parts[3]);
        byte[] expectedCheck = java.util.Arrays.copyOf(CryptoV2.sha256(scope, privateBytes, publicBytes), 8);
        if (!CryptoV2.constantTimeEquals(expectedCheck, CryptoV2.base64UrlDecode(parts[4]))) {
            throw new IllegalArgumentException("Recovery code checksum is invalid");
        }
        KeyPair pair = new KeyPair(CryptoV2.decodePublicKey(publicBytes), CryptoV2.decodePrivateKey(privateBytes));
        verifyPair(pair);
        return pair;
    }

    /** Writes a human-copyable backup outside every Minecraft/PCL instance. */
    public Path saveRecoveryBackup(String serverId, String playerName, String recoveryCode) {
        validateScope(serverId, playerName);
        Objects.requireNonNull(recoveryCode, "recoveryCode");
        return locked(() -> {
            Path directory = root.resolve("recovery-backups");
            Files.createDirectories(directory);
            restrictDirectory(directory);
            Path target = directory.resolve(recoveryFileName(serverId, playerName));
            String body = "JarsAuth recovery key for " + playerName + System.lineSeparator()
                    + "Keep this file private. On a new device, copy this whole file into the recovery-import directory."
                    + System.lineSeparator() + recoveryCode + System.lineSeparator();
            atomicWrite(target, body.getBytes(StandardCharsets.UTF_8));
            restrictFile(target);
            return target;
        });
    }

    /** Read the old device-files UUID without copying it into the new store. */
    public Optional<UUID> readLegacySecret(String serverId, String playerName) {
        if (legacyMinecraftDirectory == null) return Optional.empty();
        return readLegacySecret(legacyMinecraftDirectory, serverId, playerName);
    }

    public static Optional<UUID> readLegacySecret(
            Path minecraftDirectory, String serverId, String playerName) {
        validateScope(serverId, playerName);
        Path file = minecraftDirectory.resolve("device-files")
                .resolve(legacyFileName(serverId, playerName));
        if (!Files.isRegularFile(file)) return Optional.empty();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            JsonObject object = GSON.fromJson(reader, JsonObject.class);
            if (object == null || !object.has("deviceId")) return Optional.empty();
            return Optional.of(UUID.fromString(object.get("deviceId").getAsString()));
        } catch (RuntimeException | IOException e) {
            return Optional.empty();
        }
    }

    public static String deviceId(byte[] x509PublicKey) {
        return CryptoV2.deviceId(x509PublicKey);
    }

    public Path rootDirectory() {
        return root;
    }

    public static Path defaultRootDirectory() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String home = System.getProperty("user.home", ".");
        if (os.contains("win")) {
            String local = System.getenv("LOCALAPPDATA");
            if (local == null || local.isBlank()) {
                local = Path.of(home, "AppData", "Local").toString();
            }
            return Path.of(local, "JarsAuth");
        }
        if (os.contains("mac")) {
            return Path.of(home, "Library", "Application Support", "JarsAuth");
        }
        String xdg = System.getenv("XDG_DATA_HOME");
        if (xdg == null || xdg.isBlank()) {
            xdg = Path.of(home, ".local", "share").toString();
        }
        return Path.of(xdg, "JarsAuth");
    }

    private Credential loadOrCreateDeviceUnlocked(String serverId, String playerName) throws IOException {
        byte[] installKey = loadOrCreateInstallKey();
        Path path = scopePath(serverId, playerName);
        StoredCredential stored = readStored(path);
        if (stored != null && bindingMatches(stored, installKey)) {
            try {
                byte[] publicBytes = CryptoV2.base64Decode(stored.device.publicKey);
                KeyPair pair = decryptKeyPair(stored.device, installKey,
                        deviceAad(serverId, playerName, publicBytes));
                return new Credential(pair, stored.label, false, stored.deviceAccepted);
            } catch (RuntimeException ignored) {
                archiveUnusable(path);
            }
        } else if (stored != null) {
            archiveUnusable(path);
        }

        KeyPair pair = CryptoV2.generateEd25519KeyPair();
        long now = System.currentTimeMillis();
        StoredCredential fresh = new StoredCredential();
        fresh.version = FORMAT_VERSION;
        fresh.serverId = serverId;
        fresh.playerName = playerName;
        fresh.label = suggestLabel(pair.getPublic());
        fresh.bindingTag = bindingTag(installKey);
        fresh.device = encryptKeyPair(pair, installKey,
                deviceAad(serverId, playerName, pair.getPublic().getEncoded()));
        fresh.createdAt = now;
        fresh.updatedAt = now;
        writeStored(path, fresh);
        return new Credential(pair, fresh.label, true, false);
    }

    /** Marks the current device as accepted after the server has entered PLAY. */
    public void markDeviceAccepted(String serverId, String playerName) {
        validateScope(serverId, playerName);
        locked(() -> {
            Path path = scopePath(serverId, playerName);
            StoredCredential stored = requireStored(path);
            stored.deviceAccepted = true;
            stored.updatedAt = System.currentTimeMillis();
            writeStored(path, stored);
            return null;
        });
    }

    private byte[] loadOrCreateInstallKey() throws IOException {
        byte[] cached = cachedInstallKey;
        if (cached != null) return cached;
        ensureDirectories();
        Path path = root.resolve(windows ? "install-key.dpapi" : "install-key");
        if (Files.isRegularFile(path)) {
            try {
                byte[] stored = Files.readAllBytes(path);
                byte[] key = windows ? Crypt32Util.cryptUnprotectData(stored) : stored;
                if (key.length != CryptoV2.AES_KEY_BYTES) throw new IllegalStateException("wrong key length");
                cachedInstallKey = key;
                return key;
            } catch (RuntimeException e) {
                archiveUnusable(path);
            }
        }
        byte[] key = CryptoV2.randomBytes(CryptoV2.AES_KEY_BYTES);
        byte[] stored = windows ? Crypt32Util.cryptProtectData(key) : key;
        atomicWrite(path, stored);
        restrictFile(path);
        cachedInstallKey = key;
        return key;
    }

    private boolean bindingMatches(StoredCredential stored, byte[] installKey) {
        if (stored.version != FORMAT_VERSION || stored.bindingTag == null) return false;
        try {
            return CryptoV2.constantTimeEquals(CryptoV2.base64Decode(stored.bindingTag),
                    CryptoV2.base64Decode(bindingTag(installKey)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private String bindingTag(byte[] installKey) {
        return CryptoV2.base64(CryptoV2.hmacSha256(installKey,
                "JarsAuth/install-binding/v2\0".getBytes(StandardCharsets.US_ASCII),
                machineBindingMaterial));
    }

    private EncryptedKey encryptKeyPair(KeyPair pair, byte[] installKey, byte[] aad) {
        CryptoV2.AesGcmCiphertext encrypted = CryptoV2.aesGcmEncrypt(
                installKey, pair.getPrivate().getEncoded(), aad);
        EncryptedKey value = new EncryptedKey();
        value.algorithm = CryptoV2.KEY_ALGORITHM;
        value.publicKey = CryptoV2.base64(pair.getPublic().getEncoded());
        value.nonce = CryptoV2.base64(encrypted.nonce());
        value.privateKeyCiphertext = CryptoV2.base64(encrypted.ciphertext());
        return value;
    }

    private KeyPair decryptKeyPair(EncryptedKey encrypted, byte[] installKey, byte[] aad) {
        if (encrypted == null || !CryptoV2.KEY_ALGORITHM.equals(encrypted.algorithm)) {
            throw new IllegalArgumentException("Unsupported stored key");
        }
        PublicKey publicKey = CryptoV2.decodePublicKey(CryptoV2.base64Decode(encrypted.publicKey));
        PrivateKey privateKey = CryptoV2.decodePrivateKey(CryptoV2.aesGcmDecrypt(
                installKey, CryptoV2.base64Decode(encrypted.nonce),
                CryptoV2.base64Decode(encrypted.privateKeyCiphertext), aad));
        KeyPair pair = new KeyPair(publicKey, privateKey);
        verifyPair(pair);
        return pair;
    }

    private static void verifyPair(KeyPair pair) {
        byte[] test = CryptoV2.randomBytes(24);
        if (!CryptoV2.verify(pair.getPublic(), test, CryptoV2.sign(pair.getPrivate(), test))) {
            throw new IllegalArgumentException("Public and private keys do not match");
        }
    }

    private byte[] deviceAad(String serverId, String playerName, byte[] publicKey) {
        return CryptoV2.transcript("JARSAUTH-DEVICE-STORE",
                CryptoV2.text(serverId), CryptoV2.text(playerName), CryptoV2.bytes(publicKey));
    }

    private byte[] recoveryAad(String serverId, String playerName, String publicKey) {
        return recoveryAad(serverId, playerName, CryptoV2.base64Decode(publicKey));
    }

    private byte[] recoveryAad(String serverId, String playerName, byte[] publicKey) {
        return CryptoV2.transcript("JARSAUTH-RECOVERY-STORE",
                CryptoV2.text(serverId), CryptoV2.text(playerName), CryptoV2.bytes(publicKey));
    }

    private Path scopePath(String serverId, String playerName) {
        byte[] scope = CryptoV2.transcript("JARSAUTH-CREDENTIAL-PATH",
                CryptoV2.text(serverId), CryptoV2.text(playerName.toLowerCase(Locale.ROOT)));
        return credentialsDirectory.resolve(CryptoV2.hex(CryptoV2.sha256(scope)) + ".json");
    }

    private StoredCredential requireStored(Path path) throws IOException {
        StoredCredential stored = readStored(path);
        if (stored == null) throw new IOException("Credential disappeared while locked");
        return stored;
    }

    private StoredCredential readStored(Path path) throws IOException {
        if (!Files.isRegularFile(path)) return null;
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return GSON.fromJson(reader, StoredCredential.class);
        } catch (RuntimeException e) {
            archiveUnusable(path);
            return null;
        }
    }

    private void writeStored(Path path, StoredCredential stored) throws IOException {
        atomicWrite(path, GSON.toJson(stored).getBytes(StandardCharsets.UTF_8));
        restrictFile(path);
    }

    private void ensureDirectories() throws IOException {
        Files.createDirectories(credentialsDirectory);
        restrictDirectory(root);
        restrictDirectory(credentialsDirectory);
    }

    private void atomicWrite(Path path, byte[] value) throws IOException {
        Files.createDirectories(path.getParent());
        Path temporary = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
        restrictFile(temporary);
        try {
            Files.write(temporary, value, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void archiveUnusable(Path path) throws IOException {
        if (!Files.exists(path)) return;
        Path archived = path.resolveSibling(path.getFileName() + ".unusable-" + Instant.now().toEpochMilli());
        Files.move(path, archived, StandardCopyOption.REPLACE_EXISTING);
        restrictFile(archived);
    }

    private <T> T locked(IoSupplier<T> operation) {
        synchronized (JVM_FILE_LOCK) {
            try {
                ensureDirectories();
                Path lockPath = root.resolve(".store.lock");
                try (FileChannel channel = FileChannel.open(lockPath,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                     FileLock ignored = channel.lock()) {
                    restrictFile(lockPath);
                    return operation.get();
                }
            } catch (IOException e) {
                throw new CredentialStoreException("Could not access JarsAuth credential store", e);
            }
        }
    }

    private byte[] calculateMachineBindingMaterial() {
        StringBuilder value = new StringBuilder(128)
                .append(System.getProperty("os.name", "")).append('\0')
                .append(System.getProperty("os.arch", "")).append('\0')
                .append(System.getProperty("user.name", "")).append('\0')
                .append(System.getProperty("user.home", ""));
        if (!windows) {
            for (Path candidate : new Path[]{Path.of("/etc/machine-id"), Path.of("/var/lib/dbus/machine-id")}) {
                try {
                    if (Files.isRegularFile(candidate)) {
                        value.append('\0').append(Files.readString(candidate, StandardCharsets.US_ASCII).strip());
                        break;
                    }
                } catch (IOException ignored) {
                }
            }
        }
        String host = System.getenv(windows ? "COMPUTERNAME" : "HOSTNAME");
        if (host != null) value.append('\0').append(host);
        return CryptoV2.sha256(value.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String suggestLabel(PublicKey publicKey) {
        String host = System.getenv(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")
                ? "COMPUTERNAME" : "HOSTNAME");
        if (host == null || host.isBlank()) host = System.getProperty("user.name", "device");
        String id = CryptoV2.deviceId(publicKey);
        return host + "-" + id.substring(0, 6);
    }

    private static String legacyFileName(String serverId, String playerName) {
        try {
            byte[] digest = MessageDigest.getInstance("MD5")
                    .digest(serverId.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest) + "." + playerName + ".json";
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] recoveryScope(String serverId, String playerName) {
        validateScope(serverId, playerName);
        return java.util.Arrays.copyOf(CryptoV2.sha256(CryptoV2.transcript("JARSAUTH-RECOVERY-SCOPE",
                CryptoV2.text(serverId), CryptoV2.text(playerName.toLowerCase(Locale.ROOT)))), 16);
    }

    private static String recoveryFileName(String serverId, String playerName) {
        String safePlayerName = playerName.replaceAll("[^A-Za-z0-9_.-]", "_");
        return safePlayerName + "-" + CryptoV2.hex(recoveryScope(serverId, playerName)).substring(0, 12) + ".txt";
    }

    private static void validateScope(String serverId, String playerName) {
        if (serverId == null || serverId.isBlank()) throw new IllegalArgumentException("serverId is blank");
        if (playerName == null || playerName.isBlank()) throw new IllegalArgumentException("playerName is blank");
    }

    private static void restrictDirectory(Path path) {
        try {
            Files.setPosixFilePermissions(path, DIRECTORY_PERMISSIONS);
        } catch (IOException | UnsupportedOperationException ignored) {
        }
    }

    private static void restrictFile(Path path) {
        try {
            Files.setPosixFilePermissions(path, FILE_PERMISSIONS);
        } catch (IOException | UnsupportedOperationException ignored) {
        }
    }

    public record Credential(KeyPair keyPair, String label, boolean isNew, boolean accepted) {
        public Credential {
            Objects.requireNonNull(keyPair, "keyPair");
            Objects.requireNonNull(label, "label");
        }

        public String deviceId() {
            return CryptoV2.deviceId(keyPair.getPublic());
        }
    }

    private static final class StoredCredential {
        int version;
        String serverId;
        String playerName;
        String label;
        String bindingTag;
        EncryptedKey device;
        EncryptedKey recovery;
        EncryptedKey pendingRecovery;
        boolean pendingRecoveryImported;
        boolean deviceAccepted;
        long createdAt;
        long updatedAt;
    }

    private static final class EncryptedKey {
        String algorithm;
        String publicKey;
        String nonce;
        String privateKeyCiphertext;
    }

    @FunctionalInterface
    private interface IoSupplier<T> {
        T get() throws IOException;
    }

    public static final class CredentialStoreException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public CredentialStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
