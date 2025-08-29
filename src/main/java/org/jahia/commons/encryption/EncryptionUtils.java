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

    // Default values for backward compatibility
    private static final String DEFAULT_PASSWORD = new String(new byte[] { 74, 97, 104, 105, 97, 32, 120, 67, 77, 32, 54, 46, 53 });

    // Lazy initialization for string encryptor
    private static volatile StringEncryptor encryptorInstance;
    private static final Object ENCRYPTOR_LOCK = new Object();

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
        synchronized (ENCRYPTOR_LOCK) {
            if (encryptorInstance != null && !force) {
                throw new IllegalStateException("Encryptor already initialized. This method must be called before any encryption operations.");
            }
            encryptorInstance = createEncryptor(password, algorithm);
        }
    }

    /**
     * Creates a new encryptor instance with the specified or configured parameters.
     *
     * @param password the encryption password (if null, uses configuration or default)
     * @param algorithm the encryption algorithm (if null, uses configuration or default)
     * @return configured encryptor instance
     */
    private static StandardPBEStringEncryptor createEncryptor(String password, String algorithm) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();

        String finalPassword = password != null ? password :
            ConfigurationUtils.getConfigValue(ENCRYPTOR_PASSWORD_ENV, ENCRYPTOR_PASSWORD_PROP, DEFAULT_PASSWORD);
        String finalAlgorithm = algorithm != null ? algorithm :
            ConfigurationUtils.getConfigValue(ENCRYPTOR_ALGORITHM_ENV, ENCRYPTOR_ALGORITHM_PROP, StandardPBEByteEncryptor.DEFAULT_ALGORITHM);

        encryptor.setPassword(finalPassword);
        encryptor.setAlgorithm(finalAlgorithm);
        return encryptor;
    }

    private static StringEncryptor getStringEncryptor() {
        if (encryptorInstance == null) {
            synchronized (ENCRYPTOR_LOCK) {
                if (encryptorInstance == null) {
                    // Use configuration-based initialization if not explicitly initialized
                    encryptorInstance = createEncryptor(null, null);
                }
            }
        }
        return encryptorInstance;
    }
}
