package org.jahia.commons.encryption;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * Routes a value to the reader for the format it carries: {@link AesGcmStringEncryptor#MARKER} selects the
 * marked reader, and any other value is read by the jasypt reader.
 *
 * <p>Exactly one key is tried per value. A value is never handed to a second reader, because an
 * unauthenticated format accepts a wrong key often enough that returning bytes would be worse than
 * refusing.</p>
 */
final class VersionedStringEncryptor implements StringEncryptor {

    private final StringEncryptor writer;
    private final StringEncryptor markedReader;
    private final StringEncryptor legacyReader;
    private final boolean usingDefaultKey;

    /**
     * @param writer the encryptor every new value goes through
     * @param markedReader reads a value carrying the marker, or null when no key for that format is available
     * @param legacyReader reads a value carrying no marker
     * @param usingDefaultKey whether the writer holds the key shipped with this library
     */
    VersionedStringEncryptor(StringEncryptor writer, StringEncryptor markedReader, StringEncryptor legacyReader,
            boolean usingDefaultKey) {
        this.writer = writer;
        this.markedReader = markedReader;
        this.legacyReader = legacyReader;
        this.usingDefaultKey = usingDefaultKey;
    }

    @Override
    public String encrypt(String message) {
        return writer.encrypt(message);
    }

    @Override
    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null || !encryptedMessage.startsWith(AesGcmStringEncryptor.MARKER)) {
            return legacyReader.decrypt(encryptedMessage);
        }
        if (markedReader == null) {
            throw new EncryptionOperationNotPossibleException();
        }
        return markedReader.decrypt(encryptedMessage);
    }

    /**
     * @return whether new values are sealed with the key shipped with this library
     */
    boolean isUsingDefaultKey() {
        return usingDefaultKey;
    }
}
