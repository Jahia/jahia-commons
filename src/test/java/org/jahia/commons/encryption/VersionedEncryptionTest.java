package org.jahia.commons.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Base64;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Covers the two value formats: which key reads which value, and which values are refused.
 */
public class VersionedEncryptionTest {

    private static final String PASSWORD_PROP = "jahia-commons.encryptor.password";
    private static final String ALGORITHM_PROP = "jahia-commons.encryptor.algorithm";
    private static final String LEGACY_PASSWORD_PROP = "jahia-commons.encryptor.legacy.password";

    private static final String MARKER = "{v2}";

    // Two keys of raw material, and a passphrase that happens to be Base64 of 32 bytes.
    private static final String KEY_A = "base64:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final String KEY_B = "base64:ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";
    private static final String PASSPHRASE_SHAPED_LIKE_A_KEY = "yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5uc=";

    // Produced by jasypt 1.9.3 outside this codebase, under the password shipped with this library, so the
    // suite reads a value it did not write itself.
    private static final String EARLIER_VALUE = "value-from-an-earlier-version";
    private static final String EARLIER_ENVELOPE = "j+9rrpqFfEUdZiep6qzPj5Et7spc49pWmeG/3LbZZ5xxtWwQsj9NbA==";

    // A stored value in the marked format, sealed under KEY_A.
    private static final String MARKED_ENVELOPE_UNDER_KEY_A =
            "{v2}pQeTlA86anKNLYv+ssG11k8LvXnC+x3xf8Bx3CyvFAyvFO2SXIP8k3yhWBogS/260PU=";

    // Produced the same way, under a password of the installation's own.
    private static final String SITE_PASSWORD = "site-owned-key";
    private static final String SITE_VALUE = "value-under-a-site-key";
    private static final String SITE_ENVELOPE = "7kcOkZ+19f6zRCgU6bo+c4JZa9UWfH6MmpnphkCHxTA=";

    @Before
    public void clearConfiguration() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(ALGORITHM_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
    }

    @After
    public void restoreConfiguration() {
        clearConfiguration();
    }

    @Test
    public void aValueFromAnEarlierVersionIsReadableWhenNothingIsConfigured() {
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    @Test
    public void aValueFromAnEarlierVersionIsReadableUnderAKeyOfTheInstallationsOwn() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    @Test
    public void aValueFromAnEarlierVersionIsReadableWhenTheApplicationNamesItsKey() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, SITE_PASSWORD, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(SITE_ENVELOPE));
    }

    @Test
    public void aValueFromAnEarlierVersionIsReadableWhenTheLegacyPropertyNamesItsKey() {
        System.setProperty(LEGACY_PASSWORD_PROP, SITE_PASSWORD);
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(SITE_ENVELOPE));
    }

    @Test
    public void aValueFromAnEarlierVersionIsRefusedWhenTheLegacyPropertyNamesAnotherKey() {
        System.setProperty(LEGACY_PASSWORD_PROP, "another-key");
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        refuses(SITE_ENVELOPE);
    }

    /**
     * Pins the reach of that default. It follows a password this library resolves from the configuration, and
     * it cannot follow a password the application supplies, because the configuration does not hold that one.
     * An application that supplies a password names the legacy key in the same call.
     */
    @Test
    public void aPasswordTheApplicationSuppliesDoesNotBecomeTheLegacyKey() {
        EncryptionUtils.initializeEncryptor(SITE_PASSWORD, null, null, true);

        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
        refuses(SITE_ENVELOPE);
    }

    @Test
    public void theLegacyKeyDefaultsToTheConfiguredPassword() {
        System.setProperty(PASSWORD_PROP, SITE_PASSWORD);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(SITE_ENVELOPE));
    }

    /**
     * Pins the stored form itself, so a change to the marker, the initialization vector length or the tag
     * length shows up as a value this version can no longer read.
     */
    @Test
    public void aStoredMarkedValueIsReadableUnderTheKeyThatSealedIt() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(MARKED_ENVELOPE_UNDER_KEY_A));
    }

    @Test
    public void aNewValueCarriesTheMarkerAndIsReadable() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        String encrypted = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        assertTrue("A new value should carry the marker", encrypted.startsWith(MARKER));
        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(encrypted));
    }

    @Test
    public void twoValuesOfTheSameTextDifferAndBothRead() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        String first = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);
        String second = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        assertNotEquals("Each value should carry its own initialization vector", first, second);
        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(first));
        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(second));
    }

    @Test
    public void aValueSealedUnderOneKeyIsRefusedUnderAnother() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);
        String sealedUnderA = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        EncryptionUtils.initializeEncryptor(KEY_B, null, null, true);

        refuses(sealedUnderA);
    }

    @Test
    public void anAlteredValueIsRefused() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);
        String encrypted = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        int position = MARKER.length() + 4;
        char current = encrypted.charAt(position);
        String altered = encrypted.substring(0, position) + (current == 'A' ? 'B' : 'A')
                + encrypted.substring(position + 1);

        assertNotEquals(encrypted, altered);
        refuses(altered);
    }

    @Test
    public void aValueTooShortToHoldAnInitializationVectorAndATagIsRefused() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        refuses(MARKER + Base64.getEncoder().encodeToString(new byte[27]));
    }

    @Test
    public void aValueThatIsNotBase64IsRefused() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        refuses(MARKER + "not base64 at all");
    }

    @Test
    public void aMarkedValueIsRefusedWhenNoKeyIsConfigured() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);
        String marked = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        EncryptionUtils.initializeEncryptor(null, null, null, true);

        refuses(marked);
    }

    @Test
    public void rawKeyMaterialOfTheWrongLengthIsRefusedWhenTheEncryptorIsBuilt() {
        String halfLength = "base64:" + Base64.getEncoder().encodeToString(new byte[16]);
        try {
            EncryptionUtils.initializeEncryptor(halfLength, null, null, true);
            fail("Raw key material of the wrong length should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should state the length required, and got: " + e.getMessage(),
                    e.getMessage().contains("32 bytes"));
        }
    }

    @Test
    public void rawKeyMaterialThatIsNotBase64IsRefusedWhenTheEncryptorIsBuilt() {
        try {
            EncryptionUtils.initializeEncryptor("base64:not base64 at all", null, null, true);
            fail("Raw key material that is not Base64 should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the prefix, and got: " + e.getMessage(),
                    e.getMessage().contains("base64:"));
        }
    }

    @Test
    public void aSecretWithoutThePrefixIsAPassphraseWhateverItLooksLike() {
        EncryptionUtils.initializeEncryptor(PASSPHRASE_SHAPED_LIKE_A_KEY, null, null, true);
        String sealedUnderThePassphrase = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        EncryptionUtils.initializeEncryptor("base64:" + PASSPHRASE_SHAPED_LIKE_A_KEY, null, null, true);

        refuses(sealedUnderThePassphrase);
    }

    @Test
    public void aPassphraseReachesTheSameKeyOnEveryStartup() {
        EncryptionUtils.initializeEncryptor(SITE_PASSWORD, null, null, true);
        String sealed = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        EncryptionUtils.initializeEncryptor(SITE_PASSWORD, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(sealed));
    }

    @Test
    public void withNothingConfiguredANewValueStaysInTheFormatEarlierVersionsRead() {
        String encrypted = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        assertFalse("A value written with no configured key should carry no marker", encrypted.startsWith(MARKER));

        StandardPBEStringEncryptor stockJasypt = new StandardPBEStringEncryptor();
        stockJasypt.setPassword(EncryptionUtils.DEFAULT_PASSWORD);
        assertEquals(SITE_VALUE, stockJasypt.decrypt(encrypted));
    }

    @Test
    public void withOnlyTheLegacyPropertySetANewValueIsWrittenUnderTheKeyThatReadsItBack() {
        System.setProperty(LEGACY_PASSWORD_PROP, SITE_PASSWORD);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        String encrypted = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        assertFalse("A value written with no configured key should carry no marker", encrypted.startsWith(MARKER));
        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(encrypted));
    }

    @Test
    public void theDefaultKeyIsReportedOnlyForTheKeyThatSealsNewValues() {
        assertTrue("Nothing configured leaves new values under the shipped password",
                EncryptionUtils.isUsingDefaultKey());

        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.DEFAULT_PASSWORD);
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertFalse("A key of the installation's own seals new values, whatever reads the earlier ones",
                EncryptionUtils.isUsingDefaultKey());
    }

    private static void refuses(String value) {
        try {
            String decrypted = EncryptionUtils.passwordBaseDecrypt(value);
            fail("Expected the value to be refused, and it read back as: " + decrypted);
        } catch (EncryptionOperationNotPossibleException e) {
            // the value is refused rather than read under a key that did not write it
        }
    }
}
