package org.jahia.commons.encryption;

import org.jasypt.encryption.StringEncryptor;

/**
 * A {@link StringEncryptor} that reads two formats and writes one.
 *
 * <p>A stored value produced by the legacy password-based encryptor carries no marker for its algorithm and no marker
 * for its version, so a reader cannot tell the two formats apart by inspection of the bytes. This class removes that
 * limit. It routes a value that carries the {@link AesGcmStringEncryptor#PREFIX} marker to the AES-GCM encryptor, and
 * it routes every other value to the legacy encryptor. A value stored before an upgrade therefore stays readable, and
 * no migration step is needed before the upgrade.</p>
 */
final class VersionedStringEncryptor implements StringEncryptor {

    private final StringEncryptor writer;
    private final StringEncryptor legacyReader;
    private final AesGcmStringEncryptor markedReader;

    /**
     * @param writer the encryptor that produces every new value
     * @param legacyReader the encryptor that reads a value with no marker
     * @param markedReader the encryptor that reads a value with the marker
     */
    VersionedStringEncryptor(StringEncryptor writer, StringEncryptor legacyReader, AesGcmStringEncryptor markedReader) {
        this.writer = writer;
        this.legacyReader = legacyReader;
        this.markedReader = markedReader;
    }

    @Override
    public String encrypt(String message) {
        return writer.encrypt(message);
    }

    @Override
    public String decrypt(String encryptedMessage) {
        return AesGcmStringEncryptor.isOwnFormat(encryptedMessage)
                ? markedReader.decrypt(encryptedMessage)
                : legacyReader.decrypt(encryptedMessage);
    }
}
