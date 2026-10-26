package org.jahia.commons.encryption;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The keys of the marked format an installation holds: one primary key, which seals every new value, and
 * read-only keys, which open values without sealing any. The next key is the read-only key about to become
 * the primary one, and the others open the values sealed before the primary key replaced them. Each key is
 * found by the key id a value carries, so a value is tried under one key only.
 *
 * <p>A ring may hold no primary key, while an installation that seals in the earlier format learns the key
 * it is about to seal with.</p>
 */
final class KeyRing {

    private final AesGcmStringEncryptor primary;
    private final Map<String, AesGcmStringEncryptor> byKeyId;

    /**
     * @param primarySecret the secret of the key that seals new values, or null when none does
     * @param nextSecret the secret of the key about to become the primary one, or null when none is named
     * @param readOnlySecrets the secrets of the keys that only open values, in the order they were named
     * @throws IllegalArgumentException if two of the secrets are the same, or yield the same key id, which is
     *             the case when one key is named twice, once as a passphrase and once as the key it derives
     */
    KeyRing(String primarySecret, String nextSecret, List<String> readOnlySecrets) {
        // The same secret written twice is caught here, before any passphrase is stretched.
        if (primarySecret != null && primarySecret.equals(nextSecret)) {
            throw promotedKeyLeftAsNext(null);
        }
        Set<String> secrets = new HashSet<>();
        if (primarySecret != null) {
            secrets.add(primarySecret);
        }
        List<String> otherSecrets = new ArrayList<>();
        if (nextSecret != null) {
            otherSecrets.add(nextSecret);
        }
        otherSecrets.addAll(readOnlySecrets);
        for (String secret : otherSecrets) {
            if (!secrets.add(secret)) {
                throw new IllegalArgumentException("One key is named twice. Name each key once, either as the "
                        + "primary key, as the next key or as a read-only key.");
            }
        }
        primary = primarySecret != null ? AesGcmStringEncryptor.forSecret(primarySecret) : null;
        Map<String, AesGcmStringEncryptor> keys = new LinkedHashMap<>();
        if (primary != null) {
            keys.put(primary.getKeyId(), primary);
        }
        for (String secret : otherSecrets) {
            AesGcmStringEncryptor key = AesGcmStringEncryptor.forSecret(secret);
            if (keys.putIfAbsent(key.getKeyId(), key) != null) {
                if (secret.equals(nextSecret) && primary != null && primary.getKeyId().equals(key.getKeyId())) {
                    throw promotedKeyLeftAsNext(key.getKeyId());
                }
                // A ring holding one key twice is a configuration that was not meant: the usual one is a
                // primary key left in the read-only list after it was promoted.
                throw new IllegalArgumentException("The key with id " + key.getKeyId() + " is named twice. "
                        + "Name each key once, either as the primary key, as the next key or as a read-only key.");
            }
        }
        byKeyId = Collections.unmodifiableMap(keys);
    }

    private static IllegalArgumentException promotedKeyLeftAsNext(String keyId) {
        return new IllegalArgumentException("The next key" + (keyId != null ? ", with id " + keyId + "," : "")
                + " is also the primary key. Once a key is promoted to the primary key, remove it from the next "
                + "key, and name the key it replaces as a read-only key.");
    }

    /**
     * @return the key that seals new values, or null when none does
     */
    AesGcmStringEncryptor primary() {
        return primary;
    }

    /**
     * @param keyId a key id read from a value
     * @return the key with that id, or null when the ring holds none
     */
    AesGcmStringEncryptor forKeyId(String keyId) {
        return byKeyId.get(keyId);
    }
}
