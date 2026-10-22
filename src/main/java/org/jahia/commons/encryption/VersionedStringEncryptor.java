package org.jahia.commons.encryption;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * Routes a value to the reader for the format it carries: {@link AesGcmStringEncryptor#MARKER} selects the
 * key of the ring that the value's key id names, and any other value is read by the jasypt reader.
 *
 * <p>Exactly one key is tried per value. A value is never handed to a second reader, because an
 * unauthenticated format accepts a wrong key often enough that returning bytes would be worse than
 * refusing.</p>
 */
final class VersionedStringEncryptor implements StringEncryptor {

    private final StringEncryptor writer;
    private final KeyRing ring;
    private final StringEncryptor legacyReader;
    private final boolean usingDefaultKey;

    /**
     * @param writer the encryptor every new value goes through
     * @param ring reads a value carrying the marker, or null when no key for that format is available
     * @param legacyReader reads a value carrying no marker, or null when the installation closed that reader
     * @param usingDefaultKey whether the writer holds the key shipped with this library
     */
    VersionedStringEncryptor(StringEncryptor writer, KeyRing ring, StringEncryptor legacyReader,
            boolean usingDefaultKey) {
        this.writer = writer;
        this.ring = ring;
        this.legacyReader = legacyReader;
        this.usingDefaultKey = usingDefaultKey;
    }

    @Override
    public String encrypt(String message) {
        return writer.encrypt(message);
    }

    @Override
    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }
        if (!encryptedMessage.startsWith(AesGcmStringEncryptor.MARKER)) {
            if (legacyReader == null) {
                throw new EncryptionOperationNotPossibleException("The value carries no "
                        + AesGcmStringEncryptor.MARKER + " marker, and this installation closed the reader of "
                        + "such values with " + EncryptionUtils.NO_KEY_TOKEN + ".");
            }
            return legacyReader.decrypt(encryptedMessage);
        }
        if (ring == null) {
            // Live on a clustered node that reached no key: its peers seal values this node cannot read, and
            // it seals its own in the earlier format. The message is what tells that apart from a wrong key.
            throw new EncryptionOperationNotPossibleException("The value carries the "
                    + AesGcmStringEncryptor.MARKER + " marker, and this installation has no key for that "
                    + "format. Set jahia-commons.encryptor.password to the key the value was sealed with.");
        }
        String keyId = AesGcmStringEncryptor.keyIdIn(encryptedMessage);
        if (keyId == null) {
            throw new EncryptionOperationNotPossibleException("The value carries the "
                    + AesGcmStringEncryptor.MARKER + " marker and no key id after it. Version 1.2.0 wrote values "
                    + "in that form, and this version does not read them.");
        }
        AesGcmStringEncryptor key = ring.forKeyId(keyId);
        if (key == null) {
            throw new EncryptionOperationNotPossibleException("The value was sealed under the key with id "
                    + keyId + ", and this installation holds no such key. Add that key to "
                    + "jahia-commons.encryptor.previous.<n> to read the value.");
        }
        return key.decrypt(encryptedMessage);
    }

    /**
     * @param value a stored value
     * @return whether the value is not under the primary key: it carries no marker, or it names another key,
     *         whether the ring holds that key or not. Always false when no key seals new values in the marked format, because a
     *         reseal would then write the value in the format it already has.
     */
    boolean needsReseal(String value) {
        if (value == null || ring == null) {
            return false;
        }
        return !ring.primary().getKeyId().equals(AesGcmStringEncryptor.keyIdIn(value));
    }

    /**
     * @param value a stored value
     * @return whether a key that this encryptor holds is the one the value's format names
     */
    boolean canDecrypt(String value) {
        if (value == null) {
            return true;
        }
        if (!value.startsWith(AesGcmStringEncryptor.MARKER)) {
            return legacyReader != null;
        }
        String keyId = AesGcmStringEncryptor.keyIdIn(value);
        return ring != null && keyId != null && ring.forKeyId(keyId) != null;
    }

    /**
     * @return whether new values are written in the format every earlier version reads, which is the case
     *         whenever no key of this installation's own is available to seal them
     */
    boolean isSealingInTheEarlierFormat() {
        return ring == null;
    }

    /**
     * @return whether new values are sealed with the key shipped with this library
     */
    boolean isUsingDefaultKey() {
        return usingDefaultKey;
    }
}
