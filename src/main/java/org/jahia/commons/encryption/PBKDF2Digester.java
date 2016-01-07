/**
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2016 Jahia Solutions Group SA. All rights reserved.
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

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.StringDigester;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * Digester, that uses Password-Based Key Derivation Function 2 for password hashing.
 * 
 * @author Sergiy Shyrkov
 */
public class PBKDF2Digester implements StringDigester {

    private static final char HASH_SEPARATOR = '$';

    private static final PBKDF2Digester INSTANCE = new PBKDF2Digester();

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    /**
     * Returns a singleton instance of this digester.
     * 
     * @return a singleton instance of this digester
     */
    public static PBKDF2Digester getInstance() {
        return INSTANCE;
    }

    private int hashSizeBytes = 32;

    private String id = "p";

    private int iterations = 8192;

    private RandomSaltGenerator saltGenerator;

    private int saltSizeBytes = 64;

    /**
     * Initializes an instance of this class.
     */
    public PBKDF2Digester() {
        super();
        this.saltGenerator = new RandomSaltGenerator();
    }

    public String digest(String message) {
        byte[] salt = saltGenerator.generateSalt(saltSizeBytes);

        StringBuilder result = new StringBuilder(133);

        return result.append(new String(Base64.encodeBase64(salt, false), UTF_8)).append(HASH_SEPARATOR)
                .append(hash(message, salt)).toString();
    }

    private byte[] doHash(String pwd, byte[] salt) {
        if (pwd == null || pwd.length() == 0) {
            throw new IllegalArgumentException("Empty passwords are not supported.");
        }

        SecretKey key = null;
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            key = f.generateSecret(new PBEKeySpec(pwd.toCharArray(), salt, iterations, hashSizeBytes * 8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }

        return Base64.encodeBase64(key.getEncoded(), false);
    }

    public String getId() {
        return id;
    }

    private String hash(String pwd, byte[] salt) {
        return new String(doHash(pwd, salt), UTF_8);
    }

    public boolean matches(String message, String digest) {
        if (message == null || digest == null) {
            return false;
        }

        int pos = digest.indexOf(HASH_SEPARATOR);
        if (pos == -1) {
            throw new IllegalArgumentException("Digest of improper format");
        }

        byte[] salt = Base64.decodeBase64(digest.substring(0, pos).getBytes(UTF_8));
        byte[] hash = doHash(message, salt);

        return MessageDigest.isEqual(digest.substring(pos + 1).getBytes(UTF_8), hash);
    }

    public void setHashSizeBytes(int hashSizeBytes) {
        this.hashSizeBytes = hashSizeBytes;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public void setSaltGenerator(RandomSaltGenerator saltGenerator) {
        this.saltGenerator = saltGenerator;
    }

    public void setSaltSizeBytes(int saltSizeBytes) {
        this.saltSizeBytes = saltSizeBytes;
    }
}
