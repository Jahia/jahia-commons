package org.jahia.commons.encryption;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The keys of the marked format an installation holds: one primary key, which seals every new value, and
 * read-only keys, which open the values sealed before the primary key replaced them. Each key is found by
 * the key id a value carries, so a value is tried under one key only.
 *
 * <p>A ring of read-only keys alone is the first step of a cluster taking its first key: each node reads
 * what a node already promoted to that key seals, and still seals in the earlier format itself.</p>
 */
final class KeyRing {

    private final AesGcmStringEncryptor primary;
    private final Map<String, AesGcmStringEncryptor> byKeyId;

    /**
     * @param primarySecret the secret of the key that seals new values, or null when the ring only opens values
     * @param readOnlySecrets the secrets of the keys that only open values, in the order they were named
     * @throws IllegalArgumentException if two of the secrets are the same, or yield the same key id, which is
     *             the case when one key is named twice, once as a passphrase and once as the key it derives
     */
    KeyRing(String primarySecret, List<String> readOnlySecrets) {
        // The same secret written twice is caught here, before any passphrase is stretched.
        Set<String> secrets = new HashSet<>();
        if (primarySecret != null) {
            secrets.add(primarySecret);
        }
        for (String secret : readOnlySecrets) {
            if (!secrets.add(secret)) {
                throw new IllegalArgumentException("One key is named twice. Name each key once, either as the "
                        + "primary key or as a read-only key.");
            }
        }
        primary = primarySecret == null ? null : AesGcmStringEncryptor.forSecret(primarySecret);
        Map<String, AesGcmStringEncryptor> keys = new LinkedHashMap<>();
        if (primary != null) {
            keys.put(primary.getKeyId(), primary);
        }
        for (String secret : readOnlySecrets) {
            AesGcmStringEncryptor key = AesGcmStringEncryptor.forSecret(secret);
            if (keys.putIfAbsent(key.getKeyId(), key) != null) {
                // A ring holding one key twice is a configuration that was not meant: the usual one is a
                // primary key left in the read-only list after it was promoted.
                throw new IllegalArgumentException("The key with id " + key.getKeyId() + " is named twice. "
                        + "Name each key once, either as the primary key or as a read-only key.");
            }
        }
        byKeyId = Collections.unmodifiableMap(keys);
    }

    /**
     * @return the key that seals new values, or null when the ring holds read-only keys alone
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
