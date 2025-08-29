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

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit test for the password encryption utility.
 * 
 * @author Sergiy Shyrkov
 */
public class EncryptionUtilsTest {

    @Test
    public void testDigest() {
        Assert.assertEquals("W6ph5Mm5Pz8GgiULbPgzG37mj9g=", EncryptionUtils.sha1DigestLegacy("password"));

        String pwd = "PaSsWoRd_1234-$/����";

        String digest = EncryptionUtils.pbkdf2Digest(pwd);

        Assert.assertTrue(PBKDF2Digester.getInstance().matches(pwd, digest));
    }

    @Test
    public void testEncryptDecrypt() {
        String pwd = "PaSsWoRd_1234-$/����";

        String encrypted = EncryptionUtils.passwordBaseEncrypt(pwd);

        Assert.assertEquals(EncryptionUtils.passwordBaseDecrypt(encrypted), pwd);
    }

    @Test
    public void testDefaultConfiguration() {
        // Test that default configuration works (backward compatibility)
        String testData = "test-default-config";
        String encrypted = EncryptionUtils.passwordBaseEncrypt(testData);
        String decrypted = EncryptionUtils.passwordBaseDecrypt(encrypted);

        Assert.assertEquals("Default configuration should work", testData, decrypted);
        Assert.assertNotEquals("Encrypted data should be different from original", testData, encrypted);
        Assert.assertTrue("Encrypted data should not be empty", encrypted.length() > 0);
    }

    @Test
    public void testEncryptionConsistency() {
        // Test that multiple encryptions of the same data with same config produce different results
        // (due to salt) but decrypt to the same original value
        String testData = "consistency-test";

        String encrypted1 = EncryptionUtils.passwordBaseEncrypt(testData);
        String encrypted2 = EncryptionUtils.passwordBaseEncrypt(testData);

        // Encrypted values should be different (due to salt)
        Assert.assertNotEquals("Multiple encryptions should produce different results", encrypted1, encrypted2);

        // But both should decrypt to the same original value
        Assert.assertEquals("First encryption should decrypt correctly", testData, EncryptionUtils.passwordBaseDecrypt(encrypted1));
        Assert.assertEquals("Second encryption should decrypt correctly", testData, EncryptionUtils.passwordBaseDecrypt(encrypted2));
    }

    @Test
    public void testInitializeEncryptorWithCustomPassword() {
        try {
            // Force initialize with custom password for testing
            String customPassword = "my-custom-password-123";
            EncryptionUtils.initializeEncryptor(customPassword, null, true);

            String testData = "test-custom-password";
            String encrypted = EncryptionUtils.passwordBaseEncrypt(testData);
            String decrypted = EncryptionUtils.passwordBaseDecrypt(encrypted);

            Assert.assertEquals("Custom password initialization should work", testData, decrypted);

        } finally {
            // Reset to default configuration for other tests
            EncryptionUtils.initializeEncryptor(null, null, true);
        }
    }

    @Test
    public void testInitializeEncryptorWithCustomAlgorithm() {
        try {
            // Force initialize with custom algorithm for testing
            EncryptionUtils.initializeEncryptor(null, "PBEWithMD5AndTripleDES", true);

            String testData = "test-custom-algorithm";
            String encrypted = EncryptionUtils.passwordBaseEncrypt(testData);
            String decrypted = EncryptionUtils.passwordBaseDecrypt(encrypted);

            Assert.assertEquals("Custom algorithm initialization should work", testData, decrypted);

        } finally {
            // Reset to default configuration for other tests
            EncryptionUtils.initializeEncryptor(null, null, true);
        }
    }

    @Test
    public void testInitializeEncryptorAlreadyInitializedException() {
        // Test that attempting to initialize twice throws appropriate exception
        try {
            EncryptionUtils.initializeEncryptor("password", null);
            EncryptionUtils.initializeEncryptor("password1", null);
            Assert.fail("Expected IllegalStateException when trying to initialize already initialized encryptor");
        } catch (IllegalStateException e) {
            Assert.assertTrue("Exception message should mention already initialized",
                e.getMessage().contains("already initialized"));
        }
    }

    @Test
    public void testSystemPropertiesConfiguration() {
        String originalPassword = System.getProperty("jahia-commons.encryptor.password");
        String originalAlgorithm = System.getProperty("jahia-commons.encryptor.algorithm");

        try {
            String testData = "test-system-props";

            // First, encrypt with default configuration
            EncryptionUtils.initializeEncryptor(null, null, true); // Reset to defaults
            String encryptedWithDefaults = EncryptionUtils.passwordBaseEncrypt(testData);

            // Set system properties with different configuration
            System.setProperty("jahia-commons.encryptor.password", "system-prop-password");
            System.setProperty("jahia-commons.encryptor.algorithm", "PBEWithMD5AndTripleDES");

            // Force reinitialize to pick up the new system properties
            EncryptionUtils.initializeEncryptor(null, null, true);

            // Encrypt with the new configuration
            String encryptedWithSystemProps = EncryptionUtils.passwordBaseEncrypt(testData);
            String decrypted = EncryptionUtils.passwordBaseDecrypt(encryptedWithSystemProps);

            // Verify that encryption/decryption works with the new configuration
            Assert.assertEquals("System properties should be used for encryption/decryption", testData, decrypted);

            // Verify that the encrypted results are different (proving config was applied)
            Assert.assertNotEquals("Encrypted text should be different with different configuration",
                encryptedWithDefaults, encryptedWithSystemProps);

            // Verify that data encrypted with defaults cannot be decrypted with new config
            try {
                String attemptDecryptOldWithNew = EncryptionUtils.passwordBaseDecrypt(encryptedWithDefaults);
                Assert.fail("Should not be able to decrypt data encrypted with different password/algorithm");
            } catch (Exception e) {
                // Expected - different configuration should not be able to decrypt old data
                Assert.assertTrue("Should get encryption exception when trying to decrypt with wrong config", true);
            }

        } finally {
            // Restore original properties
            if (originalPassword != null) {
                System.setProperty("jahia-commons.encryptor.password", originalPassword);
            } else {
                System.clearProperty("jahia-commons.encryptor.password");
            }
            if (originalAlgorithm != null) {
                System.setProperty("jahia-commons.encryptor.algorithm", originalAlgorithm);
            } else {
                System.clearProperty("jahia-commons.encryptor.algorithm");
            }
            // Reset to default configuration for other tests
            EncryptionUtils.initializeEncryptor(null, null, true);
        }
    }
}
