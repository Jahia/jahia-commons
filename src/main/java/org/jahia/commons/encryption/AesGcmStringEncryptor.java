package org.jahia.commons.encryption;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * A {@link StringEncryptor} that encrypts with AES-GCM and derives its key with PBKDF2.
 *
 * <p>Every value this class produces starts with the {@value #PREFIX} marker. The marker is followed by the Base64 form
 * of three parts: the salt, the initialization vector and the output of the cipher. The braces of the marker are not
 * part of the Base64 alphabet, so a value produced here cannot be mistaken for a value produced by the legacy
 * password-based encryptor, whose output is Base64 alone.</p>
 */
final class AesGcmStringEncryptor implements StringEncryptor {

    /** The marker that every value of this format carries. */
    static final String PREFIX = "{v2}";

    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KDF_ITERATIONS = 210000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_CACHED_KEYS = 64;

    private final char[] password;
    private final SecureRandom random = new SecureRandom();

    /**
     * The salt this instance gives to every value it encrypts. One salt per instance keeps the key derivation to a
     * single PBKDF2 run for all writes. The salt defends the password against a precomputed dictionary, and that
     * defence needs the salt to be unique per installation rather than unique per value. Uniqueness per value is the
     * job of the initialization vector, which this class draws fresh for every value.
     */
    private final byte[] writeSalt = new byte[SALT_BYTES];

    /**
     * Derived keys, held by the Base64 form of their salt. A derivation costs {@value #KDF_ITERATIONS} PBKDF2 rounds,
     * and a reader may meet values written under several salts, so the last {@value #MAX_CACHED_KEYS} stay available.
     */
    private final Map<String, SecretKey> keyCache = new LinkedHashMap<String, SecretKey>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, SecretKey> eldest) {
            return size() > MAX_CACHED_KEYS;
        }
    };

    AesGcmStringEncryptor(String password) {
        if (password == null) {
            throw new IllegalArgumentException("The encryptor password cannot be null");
        }
        this.password = password.toCharArray();
        random.nextBytes(writeSalt);
    }

    /**
     * Reports whether a value carries the marker of this format.
     *
     * @param value the value to inspect, which can be null
     * @return true when the value starts with the {@value #PREFIX} marker
     */
    static boolean isOwnFormat(String value) {
        return value != null && value.startsWith(PREFIX);
    }

    @Override
    public String encrypt(String message) {
        if (message == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(writeSalt), new GCMParameterSpec(TAG_BITS, iv));
            byte[] sealed = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            byte[] envelope = ByteBuffer.allocate(writeSalt.length + iv.length + sealed.length)
                    .put(writeSalt).put(iv).put(sealed).array();
            return PREFIX + Base64.getEncoder().encodeToString(envelope);
        } catch (GeneralSecurityException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
    }

    @Override
    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }
        if (!isOwnFormat(encryptedMessage)) {
            throw new EncryptionOperationNotPossibleException();
        }
        try {
            byte[] envelope = Base64.getDecoder().decode(encryptedMessage.substring(PREFIX.length()));
            if (envelope.length <= SALT_BYTES + IV_BYTES) {
                throw new EncryptionOperationNotPossibleException();
            }
            byte[] salt = Arrays.copyOfRange(envelope, 0, SALT_BYTES);
            byte[] iv = Arrays.copyOfRange(envelope, SALT_BYTES, SALT_BYTES + IV_BYTES);
            byte[] sealed = Arrays.copyOfRange(envelope, SALT_BYTES + IV_BYTES, envelope.length);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(salt), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(sealed), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
    }

    private SecretKey deriveKey(byte[] salt) throws GeneralSecurityException {
        String cacheKey = Base64.getEncoder().encodeToString(salt);
        synchronized (keyCache) {
            SecretKey cached = keyCache.get(cacheKey);
            if (cached != null) {
                return cached;
            }
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, KDF_ITERATIONS, KEY_BITS);
        try {
            SecretKey derived = new SecretKeySpec(
                    SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded(), "AES");
            synchronized (keyCache) {
                keyCache.put(cacheKey, derived);
            }
            return derived;
        } finally {
            spec.clearPassword();
        }
    }
}
