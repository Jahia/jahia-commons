/*
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2019 Jahia Solutions Group SA. All rights reserved.
 *
 *     THIS FILE IS AVAILABLE UNDER TWO DIFFERENT LICENSES:
 *     1/GPL OR 2/JSEL
 *
 *     1/ GPL
 *     ==================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE GPL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *     2/ JSEL - Commercial and Supported Versions of the program
 *     ===================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE JSEL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     Alternatively, commercial and supported versions of the program - also known as
 *     Enterprise Distributions - must be used in accordance with the terms and conditions
 *     contained in a separate written agreement between you and Jahia Solutions Group SA.
 *
 *     If you are unsure which license is appropriate for your use,
 *     please contact the sales department at sales@jahia.com.
 */
package org.jahia.commons.encryption;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

import org.jasypt.digest.PooledStringDigester;
import org.jasypt.digest.StringDigester;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

/**
 * Miscellaneous encryption utilities.
 * 
 * @author Sergiy Shyrkov
 */
public final class EncryptionUtils {

    // Configuration keys
    private static final String ENCRYPTOR_PASSWORD_ENV = "JAHIA_COMMONS_ENCRYPTOR_PASSWORD";
    private static final String ENCRYPTOR_PASSWORD_PROP = "jahia-commons.encryptor.password";
    private static final String ENCRYPTOR_ALGORITHM_ENV = "JAHIA_COMMONS_ENCRYPTOR_ALGORITHM";
    private static final String ENCRYPTOR_ALGORITHM_PROP = "jahia-commons.encryptor.algorithm";
    private static final String ENCRYPTOR_LEGACY_PASSWORD_ENV = "JAHIA_COMMONS_ENCRYPTOR_LEGACY_PASSWORD";
    private static final String ENCRYPTOR_LEGACY_PASSWORD_PROP = "jahia-commons.encryptor.legacy.password";
    private static final String ENCRYPTOR_LEGACY_ALGORITHM_ENV = "JAHIA_COMMONS_ENCRYPTOR_LEGACY_ALGORITHM";
    private static final String ENCRYPTOR_LEGACY_ALGORITHM_PROP = "jahia-commons.encryptor.legacy.algorithm";
    private static final String ENCRYPTOR_NEXT_ENV = "JAHIA_COMMONS_ENCRYPTOR_NEXT";
    private static final String ENCRYPTOR_NEXT_PROP = "jahia-commons.encryptor.next";
    private static final String ENCRYPTOR_PREVIOUS_ENV_PREFIX = "JAHIA_COMMONS_ENCRYPTOR_PREVIOUS_";
    private static final String ENCRYPTOR_PREVIOUS_PROP_PREFIX = "jahia-commons.encryptor.previous.";

    /**
     * Names the password shipped with this library, so that a configuration points at that password without
     * holding a copy of it. It is read for the legacy key alone: an installation names the key that reads a
     * value written before it held one of its own, and this token is how it names the shipped one.
     *
     * <p>The token reads as a marker rather than as a password, so that an installation whose earlier
     * password is a plausible word does not resolve to the shipped one instead. Every character in it is
     * inert on each route an operator sets it by: it carries no <code>${}</code>, which a properties file
     * interpolates before this library sees it; it opens with no character that YAML reads as a tag, which
     * a compose file or a Kubernetes manifest would; and it triggers no history expansion in an interactive
     * shell.</p>
     */
    public static final String SHIPPED_KEY_TOKEN = "__shipped__";

    /**
     * Closes the reader of values carrying no format marker, when set as the legacy key. An installation sets
     * it once {@link #needsReseal(String)} reports no unmarked value left, so that a value nobody sealed under
     * a key of the installation's own is refused rather than read under the shipped password. It is refused
     * unless a key of the installation's own seals new values, because new values would otherwise be
     * written in the format it closes.
     */
    public static final String NO_KEY_TOKEN = "__none__";

    // Default values for backward compatibility
    static final String DEFAULT_PASSWORD = new String(new byte[] { 74, 97, 104, 105, 97, 32, 120, 67, 77, 32, 54, 46, 53 });

    // Lazy initialization for string encryptor
    private static volatile StringEncryptor encryptorInstance;
    private static final Object ENCRYPTOR_LOCK = new Object();
    private static final AtomicBoolean DEFAULT_KEY_REPORTED = new AtomicBoolean();
    private static final AtomicBoolean DEPRECATED_ALGORITHM_REPORTED = new AtomicBoolean();
    private static final AtomicBoolean EARLIER_FORMAT_REPORTED = new AtomicBoolean();
    private static final AtomicBoolean PASSPHRASE_REPORTED = new AtomicBoolean();
    private static final AtomicBoolean UNUSED_READ_ONLY_KEYS_REPORTED = new AtomicBoolean();

    // Legacy SHA-1 digester holder for legacy/deprecated methods
    private static class SHA1DigesterHolder {
        static final PooledStringDigester INSTANCE = new PooledStringDigester();

        static {
            INSTANCE.setAlgorithm("SHA-1");
            INSTANCE.setSaltSizeBytes(0);
            INSTANCE.setIterations(1);
            INSTANCE.setPoolSize(4);
        }
    }
    private static StringDigester getSHA1DigesterLegacy() {
        return SHA1DigesterHolder.INSTANCE;
    }

    /**
     * Bi-directional password base decryption of the provided text.
     * 
     * @param encrypted
     *            the text to be decrypted
     * @return password base decrypted text
     */
    public static String passwordBaseDecrypt(String encrypted) {
        return getStringEncryptor().decrypt(encrypted);
    }

    /**
     * Bi-directional password base encryption of the provided text.
     * 
     * @param source
     *            the text to be encrypted
     * @return password base encrypted text
     */
    public static String passwordBaseEncrypt(String source) {
        return getStringEncryptor().encrypt(source);
    }

    /**
     * Creates message digest using the PBKDF2 algorithm.
     * 
     * @param source
     *            the text to be hashed
     * @return digested text
     */
    public static String pbkdf2Digest(String source) {
        return pbkdf2Digest(source, false);
    }

    /**
     * Creates message digest using the PBKDF2 algorithm prefixing the result with a digester ID if requested.
     * 
     * @param source
     *            the text to be hashed
     * @param prefixWithId
     *            do we need to prefix the result with a digester ID
     * @return digested text
     */
    public static String pbkdf2Digest(String source, boolean prefixWithId) {
        PBKDF2Digester digester = PBKDF2Digester.getInstance();
        return prefixWithId ? digester.getId() + ':' + digester.digest(source) : digester.digest(source);
    }

    /**
     * Created the Base64 encoded SHA-1 (no salt) digest of the provided text. The method is introduced for compatibility with the password
     * encryption in DF prior to 7.1.0.1.
     * 
     * @param source
     *            the source text to be digested
     * @return the Base64 encoded SHA-1 digest of the provided text
     * @deprecated in Jahia 7 a more robust PBKDF2 algorithm is used for password hashing. The previous SHA-1 based algorithm is no longer used
     */
    @Deprecated
    public static String sha1DigestLegacy(String source) {
        return getSHA1DigesterLegacy().digest(source);
    }

    /**
     * Initializes an instance of this class.
     */
    private EncryptionUtils() {
        super();
    }

    /**
     * Allows applications to initialize the encryptor configuration before first use.
     * This method should be called during application startup, before any encryption operations.
     *
     * @param password the encryption password (optional, will use config/default if null)
     * @param algorithm the encryption algorithm (optional, will use config/default if null)
     * @throws IllegalStateException if the encryptor is already initialized
     */
    public static void initializeEncryptor(String password, String algorithm) {
        initializeEncryptor(password, algorithm, false);
    }

    /**
     * Allows applications to initialize the encryptor configuration before first use.
     * This method should be called during application startup, before any encryption operations.
     *
     * <p><strong>WARNING:</strong> Using the force parameter to reinitialize an encryptor that has
     * already been used may cause data encrypted with the previous configuration to become
     * undecryptable. This option is primarily intended for testing purposes.</p>
     *
     * @param password the encryption password (optional, will use config/default if null)
     * @param algorithm the encryption algorithm (optional, will use config/default if null)
     * @param force if true, allows reinitializing even if already initialized (USE WITH CAUTION)
     * @throws IllegalStateException if the encryptor is already initialized and force is false
     */
    public static void initializeEncryptor(String password, String algorithm, boolean force) {
        initializeEncryptor(password, algorithm, null, force);
    }

    /**
     * Allows applications to initialize the encryptor configuration before first use, naming the key that
     * reads a value written before the current value format.
     * This method should be called during application startup, before any encryption operations.
     *
     * <p><strong>WARNING:</strong> Using the force parameter to reinitialize an encryptor that has
     * already been used may cause data encrypted with the previous configuration to become
     * undecryptable. This option is primarily intended for testing purposes.</p>
     *
     * @param password the encryption password, which seals every new value (optional, will use
     *            config/default if null)
     * @param algorithm the encryption algorithm (optional, will use config/default if null)
     * @param legacyPassword the password that reads a value carrying no format marker (optional, will use
     *            config/default if null). An application that supplies a password of its own making has to
     *            name this one too, because the configuration default cannot see it.
     * @param force if true, allows reinitializing even if already initialized (USE WITH CAUTION)
     * @throws IllegalStateException if the encryptor is already initialized and force is false
     * @throws IllegalArgumentException if a password declared as raw key material is not of the right length
     */
    public static void initializeEncryptor(String password, String algorithm, String legacyPassword, boolean force) {
        initializeEncryptor(password, null, algorithm, legacyPassword, force);
    }

    /**
     * Allows applications to initialize the encryptor configuration before first use, naming the keys that
     * read values sealed before the current key replaced them, and the key that reads a value written before
     * the current value format.
     * This method should be called during application startup, before any encryption operations.
     *
     * <p><strong>WARNING:</strong> Using the force parameter to reinitialize an encryptor that has
     * already been used may cause data encrypted with the previous configuration to become
     * undecryptable. This option is primarily intended for testing purposes.</p>
     *
     * <p>Each passphrase, as the primary key or as a read-only key, is stretched once when the encryptor is
     * built, which takes about half a second per key. Call this method at startup so that the first
     * encryption does not pay it, and prefer {@code base64:} keys, which cost nothing to build.</p>
     *
     * <p>Read-only keys open values carrying the format marker only. A value carrying no marker is read with
     * the legacy password, so the password that wrote such values is named there, and this method refuses
     * read-only keys when no legacy password is named, by the argument or by the configuration.</p>
     *
     * @param password the encryption password, which seals every new value (optional, will use
     *            config/default if null)
     * @param previousPasswords the passwords that only read values carrying the format marker, each found by
     *            the key id a value carries (optional, will use the {@code jahia-commons.encryptor.previous.<n>}
     *            configuration if null; an empty list names none)
     * @param algorithm the encryption algorithm (optional, will use config/default if null)
     * @param legacyPassword the password that reads a value carrying no format marker (optional, will use
     *            config/default if null), {@link #SHIPPED_KEY_TOKEN} for the password shipped with this
     *            library, or {@link #NO_KEY_TOKEN} to refuse every such value
     * @param force if true, allows reinitializing even if already initialized (USE WITH CAUTION)
     * @throws IllegalStateException if the encryptor is already initialized and force is false
     * @throws IllegalArgumentException if a password declared as raw key material is not of the right length,
     *             if one key is named twice, if a token is set where it is not read, or if read-only keys are
     *             named and no legacy password is
     */
    public static void initializeEncryptor(String password, List<String> previousPasswords, String algorithm,
            String legacyPassword, boolean force) {
        initializeEncryptor(password, null, previousPasswords, algorithm, legacyPassword, force);
    }

    /**
     * Allows applications to initialize the encryptor configuration before first use, naming the key about
     * to seal new values, the keys that read values sealed before the current key replaced them, and the key
     * that reads a value written before the current value format.
     * This method should be called during application startup, before any encryption operations.
     *
     * <p>The next key opens values and seals none. A cluster names it on every node first, and makes it the
     * primary key once every node holds it, so that no node meets a value under a key it does not hold.
     * Without a primary key, new values are still written in the earlier format, and the next key opens the
     * values that nodes already promoted have sealed.</p>
     *
     * <p><strong>WARNING:</strong> Using the force parameter to reinitialize an encryptor that has
     * already been used may cause data encrypted with the previous configuration to become
     * undecryptable. This option is primarily intended for testing purposes.</p>
     *
     * <p>Each passphrase, as the primary key, as the next key or as a read-only key, is stretched once when
     * the encryptor is built, which takes about half a second per key. Call this method at startup so that
     * the first encryption does not pay it, and prefer {@code base64:} keys, which cost nothing to build.</p>
     *
     * <p>Read-only keys and the next key open values carrying the format marker only. A value carrying no
     * marker is read with the legacy password, so the password that wrote such values is named there, and this
     * method refuses read-only keys and a next key when no legacy password is named, by the argument or by the
     * configuration.</p>
     *
     * @param password the encryption password, which seals every new value (optional, will use
     *            config/default if null)
     * @param nextPassword the password about to become the encryption password, which only reads values
     *            carrying the format marker (optional, will use the {@code jahia-commons.encryptor.next}
     *            configuration if null)
     * @param previousPasswords the passwords that only read values carrying the format marker, each found by
     *            the key id a value carries (optional, will use the {@code jahia-commons.encryptor.previous.<n>}
     *            configuration if null; an empty list names none)
     * @param algorithm the encryption algorithm (optional, will use config/default if null)
     * @param legacyPassword the password that reads a value carrying no format marker (optional, will use
     *            config/default if null), {@link #SHIPPED_KEY_TOKEN} for the password shipped with this
     *            library, or {@link #NO_KEY_TOKEN} to refuse every such value
     * @param force if true, allows reinitializing even if already initialized (USE WITH CAUTION)
     * @throws IllegalStateException if the encryptor is already initialized and force is false
     * @throws IllegalArgumentException if a password declared as raw key material is not of the right length,
     *             if one key is named twice, the next key as the encryption password included, if a token is
     *             set where it is not read, or if read-only keys or a next key are named and no legacy password
     *             is
     */
    public static void initializeEncryptor(String password, String nextPassword, List<String> previousPasswords,
            String algorithm, String legacyPassword, boolean force) {
        synchronized (ENCRYPTOR_LOCK) {
            if (encryptorInstance != null && !force) {
                throw new IllegalStateException("Encryptor already initialized. This method must be called before any encryption operations.");
            }
            encryptorInstance = createEncryptor(password, nextPassword, previousPasswords, algorithm, legacyPassword);
        }
    }

    /**
     * Reports whether a stored value is not sealed under the key that seals new values, so that a caller
     * can count such values, and seal each one again by reading it and writing it back. The answer comes
     * from the format of the value alone: nothing is decrypted.
     *
     * <p>A value that names a key the ring does not hold, and a value carrying no marker once the reader of
     * that format is closed, answer true as well, and reading them is refused. A reseal therefore checks
     * {@link #canDecrypt(String)} first, and reports a value it cannot read rather than retries it.</p>
     *
     * <p>A value under the next key answers false: the nodes already promoted sealed it there, and sealing it
     * again would move it back under the key they are retiring. A next key that is abandoned is therefore
     * moved to {@code jahia-commons.encryptor.previous.<n>}, so that its values are counted again.</p>
     *
     * @param value a stored value
     * @return true when the value carries no format marker, or names a key other than the one that seals new
     *         values and the next key; false for null, for a value under the next key, and for every value
     *         when no primary key seals new values, because sealing again would write the format the value
     *         already has
     */
    public static boolean needsReseal(String value) {
        StringEncryptor current = getStringEncryptor();
        return current instanceof VersionedStringEncryptor && ((VersionedStringEncryptor) current).needsReseal(value);
    }

    /**
     * Reports whether this installation holds the key a stored value names, so that a reseal can tell a
     * value still to seal again from a value it can no longer read. The answer comes from the format of the
     * value alone: nothing is decrypted, so a value that answers true is still refused when it was altered.
     *
     * @param value a stored value
     * @return false for a value carrying the format marker and no key id, for a key id that neither the
     *         primary key, the next key nor a read-only key holds, and for a value carrying no marker once
     *         {@link #NO_KEY_TOKEN} closes the reader of that format; true otherwise, null included
     */
    public static boolean canDecrypt(String value) {
        StringEncryptor current = getStringEncryptor();
        return !(current instanceof VersionedStringEncryptor) || ((VersionedStringEncryptor) current).canDecrypt(value);
    }

    /**
     * Returns the key id a value sealed under the given secret carries. It is derived from the secret under
     * a label of its own, so it holds no material of the key that encrypts, and an application can use it to
     * tell two keys apart. A passphrase is stretched first, which takes as long as building an encryptor.
     *
     * <p>Every stored value carries this id. For raw key material, it is unique to that key. For a
     * passphrase, it is the same on every installation that holds that passphrase, and testing a guessed
     * passphrase against it costs one stretch, as a trial decryption does. A {@code base64:} key of 32
     * random bytes is therefore the secret to configure.</p>
     *
     * @param secret raw key material when it carries the {@code base64:} prefix, a passphrase otherwise
     * @return the key id, as lowercase hex
     * @throws IllegalArgumentException if the secret is blank, or if raw key material is not of the right
     *             length
     */
    public static String keyIdOf(String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("A key id is derived from a secret, and none was given.");
        }
        return AesGcmStringEncryptor.keyIdOf(secret);
    }

    /**
     * Reports whether new values are written in the format every earlier version reads, which is the case
     * whenever {@code jahia-commons.encryptor.password} names no primary key, even when a next key is held.
     *
     * <p>This is the wider of the two questions, and the one a policy asks. {@link #isUsingDefaultKey()}
     * answers for the shipped key alone, so it reports false for an installation that names a key of the
     * operator's in {@code jahia-commons.encryptor.legacy.password} and none in
     * {@code jahia-commons.encryptor.password}: such an installation writes under a key nobody else holds,
     * and still writes it in a format that carries no marker and no authentication tag.</p>
     *
     * @return true when no primary key seals new values
     */
    public static boolean isSealingInTheEarlierFormat() {
        StringEncryptor current = encryptorInstance;
        if (current instanceof VersionedStringEncryptor) {
            return ((VersionedStringEncryptor) current).isSealingInTheEarlierFormat();
        }
        return ConfigurationUtils.getConfigValue(ENCRYPTOR_PASSWORD_ENV, ENCRYPTOR_PASSWORD_PROP, null) == null;
    }

    /**
     * Reports whether the key that seals every new value is still the one shipped with this library, so that
     * an application can apply a policy this library cannot express on its own.
     *
     * <p>This answers for the key new values are written with, and for that key only. It says nothing about
     * the key that reads a value carrying no format marker
     * ({@code jahia-commons.encryptor.legacy.password}), which is the shipped one on every installation that
     * has not named another.</p>
     *
     * <p>No caller in this repository reads this outside the tests yet. Jahia core is the planned one: a
     * clustered installation generates no key of its own, so a node can run on the shipped password with a
     * log line as the only signal, and core is where the policy that refuses it belongs.</p>
     *
     * @return true when new values are sealed with the password shipped with this library
     */
    public static boolean isUsingDefaultKey() {
        StringEncryptor current = encryptorInstance;
        if (current instanceof VersionedStringEncryptor) {
            return ((VersionedStringEncryptor) current).isUsingDefaultKey();
        }
        // Nothing built yet, so answer from the configuration alone rather than build an encryptor here:
        // that would leave initializeEncryptor with nothing left to do but throw.
        return DEFAULT_PASSWORD.equals(
                ConfigurationUtils.getConfigValue(ENCRYPTOR_PASSWORD_ENV, ENCRYPTOR_PASSWORD_PROP, DEFAULT_PASSWORD));
    }

    /**
     * Creates a new encryptor instance with the specified or configured parameters. It routes a value to the
     * reader for the format that value carries, and seals every new value with one key.
     *
     * @param password the encryption password (if null, uses configuration or default)
     * @param nextPassword the password about to become the encryption password, reading a marked value only
     *            (if null, uses configuration)
     * @param previousPasswords the passwords reading a marked value only (if null, uses configuration)
     * @param algorithm the encryption algorithm (if null, uses configuration or default)
     * @param legacyPassword the password reading a value with no format marker (if null, uses configuration
     *            or default)
     * @return configured encryptor instance
     */
    private static StringEncryptor createEncryptor(String password, String nextPassword,
            List<String> previousPasswords, String algorithm, String legacyPassword) {
        String configuredSecret =
            ConfigurationUtils.getConfigValue(ENCRYPTOR_PASSWORD_ENV, ENCRYPTOR_PASSWORD_PROP, null);
        String ownSecret = password != null ? password : configuredSecret;
        String finalAlgorithm = algorithm != null ? algorithm : legacyAlgorithm();
        // A value carrying no marker was written under the password this installation configured, and under
        // the shipped one when it configured none. A password the application supplies is not visible here,
        // so an application that supplies one names this key itself.
        String legacySecretDefault = configuredSecret != null ? configuredSecret : DEFAULT_PASSWORD;
        String configuredLegacySecret =
            ConfigurationUtils.getConfigValue(ENCRYPTOR_LEGACY_PASSWORD_ENV, ENCRYPTOR_LEGACY_PASSWORD_PROP, null);
        String namedLegacySecret = legacyPassword != null ? legacyPassword : configuredLegacySecret;
        String legacySecret = namedLegacySecret != null ? namedLegacySecret : legacySecretDefault;
        // The tokens name the keys that read what is already stored. Sealing under one, or opening marked
        // values with one, is not what they mean, so they are refused here rather than taken as a passphrase
        // spelt like the token.
        refuseToken(ownSecret, ENCRYPTOR_PASSWORD_PROP);
        String nextSecret = nextPassword != null ? nextPassword :
            ConfigurationUtils.getConfigValue(ENCRYPTOR_NEXT_ENV, ENCRYPTOR_NEXT_PROP, null);
        refuseToken(nextSecret, ENCRYPTOR_NEXT_PROP);
        List<String> readOnlySecrets = readOnlySecretsOf(previousPasswords);
        refuseReadOnlyKeysWithoutALegacyKey(readOnlySecrets, namedLegacySecret);
        refuseTheNextKeyWithoutALegacyKey(nextSecret, namedLegacySecret);
        if (SHIPPED_KEY_TOKEN.equals(legacySecret)) {
            // Resolved after the argument and the configuration, so the token reaches this library by either
            // route.
            legacySecret = DEFAULT_PASSWORD;
        }
        boolean legacyReaderClosed = NO_KEY_TOKEN.equals(legacySecret);
        if (legacyReaderClosed && ownSecret == null) {
            throw new IllegalArgumentException("'" + NO_KEY_TOKEN + "' closes the reader of values carrying no "
                    + "format marker, and new values are written in that format until "
                    + ENCRYPTOR_PASSWORD_PROP + " names a key of this installation's own. Set it first.");
        }

        StringEncryptor legacyReader = legacyReaderClosed ? null : jasyptEncryptor(legacySecret, finalAlgorithm);
        // Without a key of this installation's own, new values stay in the format every version reads, under
        // the key that reads them back.
        String sealingSecret = ownSecret != null ? ownSecret : legacySecret;
        boolean usingDefaultKey = DEFAULT_PASSWORD.equals(sealingSecret);
        KeyRing ring = null;
        if (ownSecret != null) {
            ring = new KeyRing(ownSecret, nextSecret, readOnlySecrets);
        } else if (nextSecret != null) {
            // Read-only keys are reported as unused below rather than read: they name keys a primary key
            // replaced, and there is none yet.
            ring = new KeyRing(null, nextSecret, Collections.<String>emptyList());
        }
        reportKeys(ownSecret, nextSecret, readOnlySecrets, usingDefaultKey);
        StringEncryptor writer = ownSecret != null ? ring.primary() : legacyReader;
        return new VersionedStringEncryptor(writer, ring, legacyReader, usingDefaultKey);
    }

    /**
     * @param previousPasswords the read-only keys an application passes, or null to read them from the
     *            configuration
     * @return the read-only keys, each checked to be a key
     */
    private static List<String> readOnlySecretsOf(List<String> previousPasswords) {
        List<String> readOnlySecrets = previousPasswords != null ? previousPasswords :
            ConfigurationUtils.getConfigValues(ENCRYPTOR_PREVIOUS_ENV_PREFIX, ENCRYPTOR_PREVIOUS_PROP_PREFIX);
        for (String readOnlySecret : readOnlySecrets) {
            if (readOnlySecret == null || readOnlySecret.trim().isEmpty()) {
                // The configuration route treats a blank value as unset, so only an argument reaches this.
                throw new IllegalArgumentException("A read-only key, as " + ENCRYPTOR_PREVIOUS_PROP_PREFIX
                        + "<n> names one, cannot be null or blank.");
            }
            refuseToken(readOnlySecret, ENCRYPTOR_PREVIOUS_PROP_PREFIX + "<n>");
        }
        return readOnlySecrets;
    }

    /**
     * A rotation moves the old password to a read-only key, and read-only keys open marked values only. The
     * default of the legacy key would then follow the new password, which reads every unmarked value under
     * the wrong key, so the legacy key is named whenever read-only keys are.
     */
    private static void refuseReadOnlyKeysWithoutALegacyKey(List<String> readOnlySecrets, String namedLegacySecret) {
        if (!readOnlySecrets.isEmpty() && namedLegacySecret == null) {
            throw new IllegalArgumentException("Read-only keys are set in " + ENCRYPTOR_PREVIOUS_PROP_PREFIX
                    + "<n>, and they open values carrying the " + AesGcmStringEncryptor.MARKER + " marker only. "
                    + "Set " + ENCRYPTOR_LEGACY_PASSWORD_PROP + " to the password that wrote the values carrying "
                    + "no marker: '" + SHIPPED_KEY_TOKEN + "' when none was set, the earlier password when one "
                    + "was, or '" + NO_KEY_TOKEN + "' when no such value is left.");
        }
    }

    /**
     * The next key is promoted to the encryption password, and the default of the legacy key follows that
     * password, so the promotion would read every unmarked value under the wrong key. The legacy key is named
     * while the next key is, so that it is in place before the promotion.
     */
    private static void refuseTheNextKeyWithoutALegacyKey(String nextSecret, String namedLegacySecret) {
        if (nextSecret != null && namedLegacySecret == null) {
            throw new IllegalArgumentException("A next key is set in " + ENCRYPTOR_NEXT_PROP + ", and once it is "
                    + "promoted to " + ENCRYPTOR_PASSWORD_PROP + ", values carrying no marker would be read under "
                    + "it. Set " + ENCRYPTOR_LEGACY_PASSWORD_PROP + " to the password that wrote them first: '"
                    + SHIPPED_KEY_TOKEN + "' when none was set, the earlier password when one was, or '"
                    + NO_KEY_TOKEN + "' when no such value is left.");
        }
    }

    private static void reportKeys(String ownSecret, String nextSecret, List<String> readOnlySecrets,
            boolean usingDefaultKey) {
        if (ownSecret == null && !readOnlySecrets.isEmpty()) {
            reportUnusedReadOnlyKeysOnce();
        }
        if (ownSecret != null && !ownSecret.startsWith(AesGcmStringEncryptor.RAW_KEY_PREFIX)) {
            reportPassphraseOnce();
        }
        if (usingDefaultKey) {
            reportDefaultKeyOnce();
        } else if (ownSecret == null && nextSecret == null) {
            // The key is this installation's own, and it reads the stored values rather than sealing new
            // ones. A node of a cluster reaches this when the key reached its peers and not this node. A node
            // that holds the next key reads what its peers seal under it.
            reportEarlierFormatOnce();
        }
    }

    private static void refuseToken(String secret, String property) {
        if (SHIPPED_KEY_TOKEN.equals(secret) || NO_KEY_TOKEN.equals(secret)) {
            throw new IllegalArgumentException("'" + secret + "' is read for " + ENCRYPTOR_LEGACY_PASSWORD_PROP
                    + " alone, and " + property + " takes a key. Set " + property + " to a key of this "
                    + "installation's own.");
        }
    }

    /**
     * Resolves the algorithm that reads a value carrying no marker. New values are AES-GCM whatever this
     * says, so the property names the format the stored values were written in, not the one they will be
     * written in next.
     *
     * <p>{@code jahia-commons.encryptor.algorithm} named the algorithm every value was written with, and it
     * is kept as an alias of {@code jahia-commons.encryptor.legacy.algorithm} so that an installation which
     * set it keeps reading its values. Dropping it makes every unmarked value unreadable whenever the
     * algorithm was not the jasypt default.</p>
     */
    private static String legacyAlgorithm() {
        String configured = ConfigurationUtils.getConfigValue(ENCRYPTOR_LEGACY_ALGORITHM_ENV,
                ENCRYPTOR_LEGACY_ALGORITHM_PROP, null);
        if (configured != null) {
            return configured;
        }
        String deprecated =
            ConfigurationUtils.getConfigValue(ENCRYPTOR_ALGORITHM_ENV, ENCRYPTOR_ALGORITHM_PROP, null);
        if (deprecated != null) {
            reportDeprecatedAlgorithmOnce();
            return deprecated;
        }
        return StandardPBEByteEncryptor.DEFAULT_ALGORITHM;
    }

    private static void reportDeprecatedAlgorithmOnce() {
        if (DEPRECATED_ALGORITHM_REPORTED.compareAndSet(false, true)) {
            Logger.getLogger(EncryptionUtils.class.getName()).warning(
                    ENCRYPTOR_ALGORITHM_PROP + " names the algorithm that reads a value stored before this "
                            + "installation held a key of its own, and new values no longer use it. Rename it "
                            + "to " + ENCRYPTOR_LEGACY_ALGORITHM_PROP + ", and keep it set for as long as a "
                            + "value written under it is still stored.");
        }
    }

    /**
     * Clears the flags that keep each report to one line per JVM, so that a test can observe a report the
     * suite has already drawn. Nothing in production resets them: a report says what the configuration is,
     * and repeating it on every rebuild of the encryptor would say it once per deployed module.
     */
    static void resetReporting() {
        DEFAULT_KEY_REPORTED.set(false);
        DEPRECATED_ALGORITHM_REPORTED.set(false);
        EARLIER_FORMAT_REPORTED.set(false);
        PASSPHRASE_REPORTED.set(false);
        UNUSED_READ_ONLY_KEYS_REPORTED.set(false);
    }

    private static void reportPassphraseOnce() {
        if (PASSPHRASE_REPORTED.compareAndSet(false, true)) {
            Logger.getLogger(EncryptionUtils.class.getName()).warning(
                    ENCRYPTOR_PASSWORD_PROP + " holds a passphrase, and a passphrase is only as strong as it is "
                            + "hard to guess. Prefer a key of 32 random bytes, set as '"
                            + AesGcmStringEncryptor.RAW_KEY_PREFIX + "' followed by its Base64 form, which "
                            + "'openssl rand -base64 32' produces. Keep the passphrase as "
                            + ENCRYPTOR_PREVIOUS_PROP_PREFIX + "<n> until every value is sealed again. A read-only "
                            + "key opens values carrying the " + AesGcmStringEncryptor.MARKER + " marker only, so "
                            + "the password that wrote values carrying no marker goes in "
                            + ENCRYPTOR_LEGACY_PASSWORD_PROP + ".");
        }
    }

    private static void reportUnusedReadOnlyKeysOnce() {
        if (UNUSED_READ_ONLY_KEYS_REPORTED.compareAndSet(false, true)) {
            Logger.getLogger(EncryptionUtils.class.getName()).warning(
                    "Read-only keys are set in " + ENCRYPTOR_PREVIOUS_PROP_PREFIX + "<n>, and no value is read "
                            + "under them, because " + ENCRYPTOR_PASSWORD_PROP + " is not set. Set it to the key "
                            + "that seals new values.");
        }
    }

    private static void reportEarlierFormatOnce() {
        if (EARLIER_FORMAT_REPORTED.compareAndSet(false, true)) {
            Logger.getLogger(EncryptionUtils.class.getName()).warning(
                    "New values are written in the format earlier versions read, under the key named by "
                            + ENCRYPTOR_LEGACY_PASSWORD_PROP + ", because " + ENCRYPTOR_PASSWORD_PROP
                            + " is not set. On a cluster whose other nodes hold that key, this node cannot "
                            + "read what they write. Set it here to the same key they hold.");
        }
    }

    private static StringEncryptor jasyptEncryptor(String password, String algorithm) {
        return new JasyptStringEncryptor(password, algorithm);
    }

    private static void reportDefaultKeyOnce() {
        if (DEFAULT_KEY_REPORTED.compareAndSet(false, true)) {
            Logger.getLogger(EncryptionUtils.class.getName()).warning(
                "New values are sealed with the password shipped with this library. Set "
                    + ENCRYPTOR_PASSWORD_PROP + ", or the " + ENCRYPTOR_PASSWORD_ENV + " environment variable,"
                    + " to a password belonging to this installation.");
        }
    }

    private static StringEncryptor getStringEncryptor() {
        if (encryptorInstance == null) {
            synchronized (ENCRYPTOR_LOCK) {
                if (encryptorInstance == null) {
                    // Use configuration-based initialization if not explicitly initialized
                    encryptorInstance = createEncryptor(null, null, null, null, null);
                }
            }
        }
        return encryptorInstance;
    }
}
