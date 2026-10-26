package org.jahia.commons.encryption;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The keys of the marked format an installation holds: one primary key, which seals every new value, a next
 * key, which the installation is about to take, and read-only keys, which open the values sealed before the
 * primary key replaced them. Each key is found by the key id a value carries, so a value is tried under one
 * key only.
 *
 * <p>A ring without a primary key is the first step of a cluster taking its first key: each node reads what
 * a node already promoted to that key seals, and still seals in the earlier format itself.</p>
 */
final class KeyRing {

    private static final String PRIMARY = "jahia-commons.encryptor.password";
    private static final String NEXT = "jahia-commons.encryptor.next";
    private static final String READ_ONLY = "jahia-commons.encryptor.previous.<n>";

    private final AesGcmStringEncryptor primary;
    private final Map<String, AesGcmStringEncryptor> byKeyId;

    /**
     * @param primarySecret the secret of the key that seals new values, or null when the ring only opens values
     * @param nextSecret the secret of the key the installation is about to take, or null
     * @param readOnlySecrets the secrets of the keys that only open values, in the order they were named
     * @throws IllegalArgumentException if two of the secrets are the same, or yield the same key id, which is
     *             the case when one key is named twice, once as a passphrase and once as the key it derives
     */
    KeyRing(String primarySecret, String nextSecret, List<String> readOnlySecrets) {
        List<String> secrets = new ArrayList<>();
        List<String> roles = new ArrayList<>();
        if (primarySecret != null) {
            secrets.add(primarySecret);
            roles.add(PRIMARY);
        }
        if (nextSecret != null) {
            secrets.add(nextSecret);
            roles.add(NEXT);
        }
        for (String secret : readOnlySecrets) {
            secrets.add(secret);
            roles.add(READ_ONLY);
        }
        // The same secret written twice is caught here, before any passphrase is stretched.
        Map<String, String> roleBySecret = new HashMap<>();
        for (int i = 0; i < secrets.size(); i++) {
            String earlier = roleBySecret.putIfAbsent(secrets.get(i), roles.get(i));
            if (earlier != null) {
                throw namedTwice("One key", earlier, roles.get(i));
            }
        }
        AesGcmStringEncryptor primaryKey = null;
        Map<String, AesGcmStringEncryptor> keys = new LinkedHashMap<>();
        Map<String, String> roleByKeyId = new HashMap<>();
        for (int i = 0; i < secrets.size(); i++) {
            AesGcmStringEncryptor key = AesGcmStringEncryptor.forSecret(secrets.get(i));
            String earlier = roleByKeyId.putIfAbsent(key.getKeyId(), roles.get(i));
            if (earlier != null) {
                // A ring holding one key twice is a configuration that was not meant: the usual one is a
                // promoted key left where it was.
                throw namedTwice("The key with id " + key.getKeyId(), earlier, roles.get(i));
            }
            keys.put(key.getKeyId(), key);
            if (PRIMARY.equals(roles.get(i))) {
                primaryKey = key;
            }
        }
        primary = primaryKey;
        byKeyId = Collections.unmodifiableMap(keys);
    }

    private static IllegalArgumentException namedTwice(String which, String earlierRole, String role) {
        if (PRIMARY.equals(earlierRole) && NEXT.equals(role)) {
            return new IllegalArgumentException(which + " is named as " + NEXT + " and as " + PRIMARY + ". A key "
                    + "moved to " + PRIMARY + " leaves " + NEXT + ", so remove it from there.");
        }
        return new IllegalArgumentException(which + " is named twice, as " + earlierRole + " and as " + role
                + ". Name each key once.");
    }

    /**
     * @return the key that seals new values, or null when the ring holds no primary key
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
