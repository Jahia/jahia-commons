package org.jahia.commons.encryption;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * Reads and writes the marked value format: AES-256-GCM with one random initialization vector per value.
 *
 * <p>The stored value is {@link #MARKER}, then the Base64 form of the initialization vector followed by the
 * ciphertext and the authentication tag. The tag makes a value that was sealed with another key, or altered
 * since it was written, refuse to open rather than return bytes.</p>
 */
final class AesGcmStringEncryptor implements StringEncryptor {

    /** Marks a value stored in this format. It sits outside the Base64 alphabet, so routing is decidable. */
    static final String MARKER = "{v2}";

    /** A secret carrying this prefix is raw key material. Without it, the secret is a passphrase. */
    static final String RAW_KEY_PREFIX = "base64:";

    /** The length raw key material must decode to. */
    static final int KEY_LENGTH_BYTES = 32;

    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private static final String DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int DERIVATION_ITERATIONS = 210000;
    private static final int SALT_LENGTH_BYTES = 16;

    /** Keeps the salt of this derivation apart from any other use of the same passphrase. */
    private static final byte[] SALT_LABEL = "jahia-commons.encryptor.v2".getBytes(StandardCharsets.UTF_8);

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    private AesGcmStringEncryptor(SecretKey key) {
        this.key = key;
    }

    /**
     * Builds an encryptor for the given secret. A passphrase is stretched here, once, and the derived key is
     * held for the life of the encryptor, so no derivation runs per value.
     *
     * @param secret raw key material when it carries {@link #RAW_KEY_PREFIX}, a passphrase otherwise
     * @return an encryptor holding the key that secret names
     * @throws IllegalArgumentException if raw key material does not decode to {@link #KEY_LENGTH_BYTES} bytes
     */
    static AesGcmStringEncryptor forSecret(String secret) {
        return new AesGcmStringEncryptor(new SecretKeySpec(keyMaterialOf(secret), KEY_ALGORITHM));
    }

    @Override
    public String encrypt(String message) {
        if (message == null) {
            return null;
        }
        byte[] iv = new byte[IV_LENGTH_BYTES];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] sealed = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            byte[] envelope = Arrays.copyOf(iv, iv.length + sealed.length);
            System.arraycopy(sealed, 0, envelope, iv.length, sealed.length);
            return MARKER + Base64.getEncoder().encodeToString(envelope);
        } catch (GeneralSecurityException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
    }

    @Override
    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }
        byte[] envelope = envelopeOf(encryptedMessage);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(TAG_LENGTH_BITS, envelope, 0, IV_LENGTH_BYTES));
            byte[] plain = cipher.doFinal(envelope, IV_LENGTH_BYTES, envelope.length - IV_LENGTH_BYTES);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            // The cause travels with the refusal: a caller that logs it can tell one refusal from another.
            throw new EncryptionOperationNotPossibleException(e);
        }
    }

    private static byte[] envelopeOf(String encryptedMessage) {
        if (!encryptedMessage.startsWith(MARKER)) {
            throw new EncryptionOperationNotPossibleException("The value carries no " + MARKER + " marker.");
        }
        byte[] envelope;
        try {
            envelope = Base64.getDecoder().decode(encryptedMessage.substring(MARKER.length()));
        } catch (IllegalArgumentException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
        int shortest = IV_LENGTH_BYTES + TAG_LENGTH_BITS / Byte.SIZE;
        if (envelope.length < shortest) {
            throw new EncryptionOperationNotPossibleException("The value holds " + envelope.length
                    + " bytes, and an initialization vector and a tag need " + shortest + ".");
        }
        return envelope;
    }

    private static byte[] keyMaterialOf(String secret) {
        if (!secret.startsWith(RAW_KEY_PREFIX)) {
            return derive(secret);
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(secret.substring(RAW_KEY_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("A secret declared with the '" + RAW_KEY_PREFIX
                    + "' prefix must be Base64.", e);
        }
        if (raw.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("A secret declared with the '" + RAW_KEY_PREFIX
                    + "' prefix must decode to " + KEY_LENGTH_BYTES + " bytes, and this one decodes to "
                    + raw.length + ".");
        }
        return raw;
    }

    private static byte[] derive(String passphrase) {
        try {
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), saltFor(passphrase),
                    DERIVATION_ITERATIONS, KEY_LENGTH_BYTES * Byte.SIZE);
            return SecretKeyFactory.getInstance(DERIVATION_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot derive a key with " + DERIVATION_ALGORITHM + ".", e);
        }
    }

    /**
     * The salt comes from the passphrase itself. That keeps one installation deriving the same key on every
     * startup, and it keeps two installations that hold different passphrases on different salts.
     *
     * <p>It adds nothing against precomputation. A candidate passphrase yields its own salt, so the
     * iteration count is the whole cost of testing one candidate. An application that holds key material
     * passes it with the {@link #RAW_KEY_PREFIX} prefix and reaches none of this: the passphrase path is for
     * a password set by hand.</p>
     */
    private static byte[] saltFor(String passphrase) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(SALT_LABEL);
            digest.update(passphrase.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest.digest(), SALT_LENGTH_BYTES);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }
}
