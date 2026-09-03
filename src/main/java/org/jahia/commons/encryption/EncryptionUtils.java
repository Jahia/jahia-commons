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

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

import org.jasypt.digest.PooledStringDigester;
import org.jasypt.digest.StringDigester;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

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

    // Default values for backward compatibility
    static final String DEFAULT_PASSWORD = new String(new byte[] { 74, 97, 104, 105, 97, 32, 120, 67, 77, 32, 54, 46, 53 });

    // Lazy initialization for string encryptor
    private static volatile StringEncryptor encryptorInstance;
    private static final Object ENCRYPTOR_LOCK = new Object();
    private static final AtomicBoolean DEFAULT_KEY_REPORTED = new AtomicBoolean();

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
        synchronized (ENCRYPTOR_LOCK) {
            if (encryptorInstance != null && !force) {
                throw new IllegalStateException("Encryptor already initialized. This method must be called before any encryption operations.");
            }
            encryptorInstance = createEncryptor(password, algorithm, legacyPassword);
        }
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
     * @param algorithm the encryption algorithm (if null, uses configuration or default)
     * @param legacyPassword the password reading a value with no format marker (if null, uses configuration
     *            or default)
     * @return configured encryptor instance
     */
    private static StringEncryptor createEncryptor(String password, String algorithm, String legacyPassword) {
        String configuredPassword =
            ConfigurationUtils.getConfigValue(ENCRYPTOR_PASSWORD_ENV, ENCRYPTOR_PASSWORD_PROP, null);
        String finalPassword = password != null ? password : configuredPassword;
        String finalAlgorithm = algorithm != null ? algorithm :
            ConfigurationUtils.getConfigValue(ENCRYPTOR_ALGORITHM_ENV, ENCRYPTOR_ALGORITHM_PROP, StandardPBEByteEncryptor.DEFAULT_ALGORITHM);
        // A value carrying no marker was written under the password this installation configured, and under
        // the shipped one when it configured none. A password the application supplies is not visible here,
        // so an application that supplies one names this key itself.
        String finalLegacyPassword = legacyPassword != null ? legacyPassword :
            ConfigurationUtils.getConfigValue(ENCRYPTOR_LEGACY_PASSWORD_ENV, ENCRYPTOR_LEGACY_PASSWORD_PROP,
                configuredPassword != null ? configuredPassword : DEFAULT_PASSWORD);

        StringEncryptor legacyReader = jasyptEncryptor(finalLegacyPassword, finalAlgorithm);
        // Without a key of this installation's own, new values stay in the format every version reads, under
        // the key that reads them back.
        String sealingPassword = finalPassword != null ? finalPassword : finalLegacyPassword;
        boolean usingDefaultKey = DEFAULT_PASSWORD.equals(sealingPassword);
        if (usingDefaultKey) {
            reportDefaultKeyOnce();
        }
        AesGcmStringEncryptor markedReader =
            finalPassword == null ? null : AesGcmStringEncryptor.forSecret(finalPassword);
        StringEncryptor writer = markedReader != null ? markedReader : legacyReader;
        return new VersionedStringEncryptor(writer, markedReader, legacyReader, usingDefaultKey);
    }

    private static StringEncryptor jasyptEncryptor(String password, String algorithm) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword(password);
        encryptor.setAlgorithm(algorithm);
        return encryptor;
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
                    encryptorInstance = createEncryptor(null, null, null);
                }
            }
        }
        return encryptorInstance;
    }
}
