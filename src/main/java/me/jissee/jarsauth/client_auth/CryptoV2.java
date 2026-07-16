/*
 * This file is part of JarsAuth, licensed under the GNU GPL v3.0.
 */
package me.jissee.jarsauth.client_auth;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

/** Java 17-only cryptographic primitives shared by the JarsAuth v2 protocol. */
public final class CryptoV2 {
    public static final String KEY_ALGORITHM = "Ed25519";
    public static final String SIGNATURE_ALGORITHM = "Ed25519";
    public static final int AES_KEY_BYTES = 32;
    public static final int GCM_NONCE_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;
    public static final int CHALLENGE_BYTES = 32;

    private static final byte[] TRANSCRIPT_MAGIC = "JARSAUTH-V2\0".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();
    private static final Base64.Encoder B64_URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_URL_DECODER = Base64.getUrlDecoder();

    private CryptoV2() {
    }

    public static KeyPair generateEd25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance(KEY_ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 is unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(key, RANDOM);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not create Ed25519 signature", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signatureBytes) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signatureBytes, "signatureBytes");
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(key);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static PrivateKey decodePrivateKey(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Invalid Ed25519 PKCS#8 private key", e);
        }
    }

    public static PublicKey decodePublicKey(byte[] x509) {
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(x509));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Invalid Ed25519 X.509 public key", e);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(Objects.requireNonNull(part, "hash part"));
            }
            return digest.digest();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("SHA-256 is unavailable", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] part : parts) {
                mac.update(Objects.requireNonNull(part, "HMAC part"));
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not calculate HMAC-SHA256", e);
        }
    }

    public static AesGcmCiphertext aesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad) {
        requireAesKey(key);
        byte[] nonce = randomBytes(GCM_NONCE_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce), RANDOM);
            if (aad != null) cipher.updateAAD(aad);
            return new AesGcmCiphertext(nonce, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not encrypt AES-GCM value", e);
        }
    }

    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        requireAesKey(key);
        if (nonce == null || nonce.length != GCM_NONCE_BYTES) {
            throw new IllegalArgumentException("AES-GCM nonce must be 12 bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            if (aad != null) cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM authentication failed", e);
        }
    }

    /**
     * Canonical authentication transcript. Every field is length-prefixed and
     * null is distinct from an empty value. Both peers must pass fields in this
     * exact order; no locale-dependent normalization is performed here.
     */
    public static byte[] authenticationTranscript(
            String domain,
            byte[] sessionId,
            byte[] nonce,
            String serverId,
            String playerName,
            String mode,
            String label,
            byte[] devicePublicKey,
            byte[] recoveryPublicKey) {
        return transcript(domain,
                bytes(sessionId), bytes(nonce), text(serverId), text(playerName),
                text(mode), text(label), bytes(devicePublicKey), bytes(recoveryPublicKey));
    }

    public static byte[] loginTranscript(
            String sessionId,
            byte[] nonce,
            String serverId,
            String playerName,
            AuthMode mode,
            String label,
            byte[] devicePublicKey,
            byte[] recoveryPublicKey) {
        Objects.requireNonNull(mode, "mode");
        return authenticationTranscript("DEVICE_LOGIN",
                sessionId == null ? null : sessionId.getBytes(StandardCharsets.UTF_8),
                nonce, serverId, playerName, mode.name(), label,
                devicePublicKey, recoveryPublicKey);
    }

    public static byte[] recoveryOperationTranscript(
            String requestId, byte[] nonce, String serverId, String playerName,
            String operation, String targetDeviceId, String newLabel,
            long issuedAt, long authRevision) {
        return recoveryOperationTranscript(requestId, nonce, serverId, playerName, operation,
                targetDeviceId, newLabel, issuedAt, authRevision, new byte[0]);
    }

    public static byte[] recoveryOperationTranscript(
            String requestId, byte[] nonce, String serverId, String playerName,
            String operation, String targetDeviceId, String newLabel,
            long issuedAt, long authRevision, byte[] newRecoveryPublicKey) {
        return transcript("RECOVERY_OPERATION",
                text(requestId), bytes(nonce), text(serverId), text(playerName),
                text(operation), text(targetDeviceId), text(newLabel),
                text(Long.toString(issuedAt)), text(Long.toString(authRevision)),
                bytes(newRecoveryPublicKey));
    }

    /** Canonical, typed, length-prefixed transcript encoder for other v2 messages. */
    public static byte[] transcript(String domain, TranscriptField... fields) {
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(fields, "fields");
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(256);
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeInt(TRANSCRIPT_MAGIC.length);
            out.write(TRANSCRIPT_MAGIC);
            writeValue(out, (byte) 1, domain.getBytes(StandardCharsets.UTF_8));
            out.writeInt(fields.length);
            for (TranscriptField field : fields) {
                if (field == null) {
                    out.writeByte(0);
                    out.writeInt(-1);
                } else {
                    writeValue(out, field.type(), field.value());
                }
            }
            out.flush();
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    public static TranscriptField text(String value) {
        return new TranscriptField((byte) 1,
                value == null ? null : value.getBytes(StandardCharsets.UTF_8));
    }

    public static TranscriptField bytes(byte[] value) {
        return new TranscriptField((byte) 2, value == null ? null : value.clone());
    }

    public static byte[] randomBytes(int length) {
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    public static String base64(byte[] value) {
        return B64.encodeToString(value);
    }

    public static byte[] base64Decode(String value) {
        return B64_DECODER.decode(value);
    }

    public static String base64Url(byte[] value) {
        return B64_URL.encodeToString(value);
    }

    public static byte[] base64UrlDecode(String value) {
        return B64_URL_DECODER.decode(value);
    }

    public static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }

    public static byte[] hexDecode(String value) {
        return HexFormat.of().parseHex(value);
    }

    public static String deviceId(PublicKey publicKey) {
        return hex(sha256(publicKey.getEncoded()));
    }

    public static String deviceId(byte[] x509PublicKey) {
        Objects.requireNonNull(x509PublicKey, "x509PublicKey");
        return hex(sha256(x509PublicKey));
    }

    public static boolean constantTimeEquals(byte[] left, byte[] right) {
        return left != null && right != null && MessageDigest.isEqual(left, right);
    }

    private static void requireAesKey(byte[] key) {
        if (key == null || key.length != AES_KEY_BYTES) {
            throw new IllegalArgumentException("AES key must be 32 bytes");
        }
    }

    private static void writeValue(DataOutputStream out, byte type, byte[] value) throws IOException {
        out.writeByte(type);
        if (value == null) {
            out.writeInt(-1);
        } else {
            out.writeInt(value.length);
            out.write(value);
        }
    }

    public record TranscriptField(byte type, byte[] value) {
        public TranscriptField {
            value = value == null ? null : value.clone();
        }

        @Override
        public byte[] value() {
            return value == null ? null : value.clone();
        }
    }

    public record AesGcmCiphertext(byte[] nonce, byte[] ciphertext) {
        public AesGcmCiphertext {
            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }
    }

    public static final class CryptoException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
