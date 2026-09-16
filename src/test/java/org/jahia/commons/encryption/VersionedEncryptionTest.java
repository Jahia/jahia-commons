package org.jahia.commons.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
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
    private static final String LEGACY_ALGORITHM_PROP = "jahia-commons.encryptor.legacy.algorithm";

    private static final String MARKER = "v2:";

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
            "v2:pQeTlA86anKNLYv+ssG11k8LvXnC+x3xf8Bx3CyvFAyvFO2SXIP8k3yhWBogS/260PU=";

    // Produced the same way, under a password of the installation's own.
    private static final String SITE_PASSWORD = "site-owned-key";
    private static final String SITE_VALUE = "value-under-a-site-key";
    private static final String SITE_ENVELOPE = "7kcOkZ+19f6zRCgU6bo+c4JZa9UWfH6MmpnphkCHxTA=";

    @Before
    public void clearConfiguration() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(ALGORITHM_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        System.clearProperty(LEGACY_ALGORITHM_PROP);
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

    /**
     * The token names the shipped password, so a configuration points at it without holding a copy. That is
     * what an installation upgrading from an earlier version has to name, and it is the value nobody wants
     * written into a configuration file or a documentation page.
     */
    @Test
    public void theTokenNamesTheShippedPasswordForTheLegacyKey() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);

        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    @Test
    public void theTokenReachesTheLegacyKeyThroughTheConfigurationToo() {
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    /**
     * The token is read for the legacy key alone. Naming it as the password that seals new values asks to
     * seal under the shipped password, which is what this change moves away from, so it is refused rather
     * than taken as a passphrase that happens to be spelt like the token.
     */
    @Test
    public void theTokenIsRefusedAsThePasswordThatSealsNewValues() {
        try {
            EncryptionUtils.initializeEncryptor(EncryptionUtils.SHIPPED_KEY_TOKEN, null, null, true);
            fail("The token should be refused as the password that seals new values");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the property that reads the token, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP));
        }
    }

    /**
     * An installation that named an algorithm under the earlier property keeps reading its values once the
     * property carries the name that matches what it now does.
     */
    @Test
    public void theLegacyAlgorithmReadsAValueTheDeprecatedNameWrote() {
        System.setProperty(ALGORITHM_PROP, "PBEWithMD5AndTripleDES");
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String stored = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);
        assertFalse("A value written with no configured key should carry no marker", stored.startsWith(MARKER));

        System.clearProperty(ALGORITHM_PROP);
        System.setProperty(LEGACY_ALGORITHM_PROP, "PBEWithMD5AndTripleDES");
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(stored));
    }

    @Test
    public void theLegacyAlgorithmWinsOverTheDeprecatedName() {
        System.setProperty(LEGACY_ALGORITHM_PROP, "PBEWithMD5AndTripleDES");
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String stored = EncryptionUtils.passwordBaseEncrypt(SITE_VALUE);

        System.setProperty(ALGORITHM_PROP, StandardPBEByteEncryptor.DEFAULT_ALGORITHM);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(SITE_VALUE, EncryptionUtils.passwordBaseDecrypt(stored));
    }

    /**
     * A blank secret derives a key from the empty string, which is a key every installation passing one
     * would share. The configuration routes treat a blank value as unset, so only an application passing
     * the secret as an argument reaches this.
     */
    @Test
    public void aBlankSecretIsRefused() {
        try {
            EncryptionUtils.initializeEncryptor("   ", null, null, true);
            fail("A blank secret should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the property to set, and got: " + e.getMessage(),
                    e.getMessage().contains(PASSWORD_PROP));
        }
    }

    @Test
    public void aBlankConfiguredPasswordIsReadAsUnset() {
        System.setProperty(PASSWORD_PROP, "  ");
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertFalse("A blank configured password should leave new values in the earlier format",
                EncryptionUtils.passwordBaseEncrypt(SITE_VALUE).startsWith(MARKER));
    }

    /**
     * A node that holds the key its values were written under, and no key to seal new ones with, keeps
     * writing in the earlier format. On a cluster whose other nodes hold a key, that node cannot read what
     * they write, so the report is what an operator greps for.
     */
    @Test
    public void writingInTheEarlierFormatUnderAKeyOfTheInstallationsOwnIsReported() {
        System.setProperty(LEGACY_PASSWORD_PROP, SITE_PASSWORD);

        List<String> reported = reportsOf(() -> EncryptionUtils.initializeEncryptor(null, null, null, true));

        assertEquals(1, reported.size());
        assertTrue("The report should name the property that is not set, and got: " + reported.get(0),
                reported.get(0).contains(PASSWORD_PROP));
    }

    @Test
    public void sealingUnderTheShippedPasswordIsReportedInsteadOfTheEarlierFormat() {
        List<String> reported = reportsOf(() -> EncryptionUtils.initializeEncryptor(null, null, null, true));

        assertEquals(1, reported.size());
        assertTrue("The shipped password should be the report, and got: " + reported.get(0),
                reported.get(0).contains("shipped with this library"));
    }

    @Test
    public void aKeyOfTheInstallationsOwnIsNotReported() {
        assertTrue(reportsOf(() -> EncryptionUtils.initializeEncryptor(KEY_A, null, null, true)).isEmpty());
    }

    /**
     * The case isUsingDefaultKey() cannot report: a key of the operator's reads the stored values, none
     * seals new ones, so they keep the earlier format under a key no one else holds.
     */
    @Test
    public void theEarlierFormatIsReportedForALegacyKeyOfTheOperatorsOwn() {
        System.setProperty(LEGACY_PASSWORD_PROP, SITE_PASSWORD);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertTrue("New values stay in the earlier format", EncryptionUtils.isSealingInTheEarlierFormat());
        assertFalse("The key that seals them is not the shipped one", EncryptionUtils.isUsingDefaultKey());
    }

    @Test
    public void theEarlierFormatIsReportedWithNothingConfigured() {
        assertTrue(EncryptionUtils.isSealingInTheEarlierFormat());
        assertTrue(EncryptionUtils.isUsingDefaultKey());
    }

    @Test
    public void theEarlierFormatIsNotReportedUnderAKeyOfTheInstallationsOwn() {
        EncryptionUtils.initializeEncryptor(KEY_A, null, null, true);

        assertFalse(EncryptionUtils.isSealingInTheEarlierFormat());
        assertFalse(EncryptionUtils.isUsingDefaultKey());
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

    /**
     * Runs the action with every report flag cleared, and returns what the library reported while it ran.
     */
    private static List<String> reportsOf(Runnable action) {
        List<String> reported = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord entry) {
                if (entry.getLevel().intValue() >= Level.WARNING.intValue()) {
                    reported.add(entry.getMessage());
                }
            }

            @Override
            public void flush() {
                // nothing is buffered
            }

            @Override
            public void close() {
                // nothing is held open
            }
        };
        Logger logger = Logger.getLogger(EncryptionUtils.class.getName());
        EncryptionUtils.resetReporting();
        logger.addHandler(handler);
        try {
            action.run();
        } finally {
            logger.removeHandler(handler);
        }
        return reported;
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
