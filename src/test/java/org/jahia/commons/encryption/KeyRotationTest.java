package org.jahia.commons.encryption;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Covers the key ring: one key seals, earlier keys stay readable, and each value names its key.
 */
public class KeyRotationTest {

    private static final String PASSWORD_PROP = "jahia-commons.encryptor.password";
    private static final String LEGACY_PASSWORD_PROP = "jahia-commons.encryptor.legacy.password";
    private static final String PREVIOUS_PROP = "jahia-commons.encryptor.previous.";

    private static final String KEY_1 = "base64:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final String KEY_2 = "base64:ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";
    private static final String KEY_3 = "base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final String KEY_ID_1 = "b0166dad948115e3";
    private static final String KEY_ID_2 = "3abd372c819f2560";
    // A passphrase, and the raw form of the key it derives, produced outside this codebase.
    private static final String PASSPHRASE = "site-owned-key";
    private static final String KEY_THE_PASSPHRASE_DERIVES = "base64:EqLngLvTL4Wja+BvijkrRCkzFe9DVpsns7MfBsg1KV0=";
    private static final String KEY_ID_OF_THE_PASSPHRASE = "f76d8b3299501cad";

    private static final String VALUE = "value-under-a-site-key";

    // Produced by jasypt 1.9.3 outside this codebase, under the password shipped with this library.
    private static final String EARLIER_VALUE = "value-from-an-earlier-version";
    private static final String EARLIER_ENVELOPE = "j+9rrpqFfEUdZiep6qzPj5Et7spc49pWmeG/3LbZZ5xxtWwQsj9NbA==";

    @Before
    public void clearConfiguration() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        for (int n = 0; n <= 12; n++) {
            System.clearProperty(PREVIOUS_PROP + n);
        }
        System.clearProperty(PREVIOUS_PROP + "01");
        System.clearProperty(PREVIOUS_PROP + "\u0662");
        EncryptionUtils.initializeEncryptor(null, null, null, true);
    }

    @After
    public void restoreConfiguration() {
        clearConfiguration();
    }

    @Test
    public void aValueSurvivesARotationAndAReseal() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, null, true);
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(EncryptionUtils.needsReseal(underKey1));
        String resealed = EncryptionUtils.passwordBaseEncrypt(EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(resealed.startsWith("v2:" + KEY_ID_2 + ":"));
        assertFalse(EncryptionUtils.needsReseal(resealed));

        EncryptionUtils.initializeEncryptor(KEY_2, emptyList(), null, null, true);
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(resealed));
        refusesNaming(underKey1, KEY_ID_1);
    }

    @Test
    public void readOnlyKeysComeFromTheConfiguration() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        // A number may be skipped.
        System.setProperty(PREVIOUS_PROP + "01", KEY_1);
        System.setProperty(PREVIOUS_PROP + "10", KEY_3);
        System.setProperty(PREVIOUS_PROP + "\u0662", EncryptionUtils.NO_KEY_TOKEN);
        System.setProperty(PASSWORD_PROP, KEY_2);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey3));
    }

    @Test
    public void anUnknownKeyIdNamesItself() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, null, null, true);

        refusesNaming(underKey1, KEY_ID_1);
    }

    /**
     * Rewriting the key id routes the value to another key of the ring, and that key refuses it. That the
     * prefix is authenticated is pinned by a stored value in VersionedEncryptionTest.
     */
    @Test
    public void aRelabelledValueIsRefused() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, null, true);
        String relabelled = underKey1.replace(KEY_ID_1, KEY_ID_2);

        refusesNaming(relabelled, null);
    }

    @Test
    public void aMarkedValueWithoutAWellFormedKeyIdIsRefused() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String sealed = EncryptionUtils.passwordBaseEncrypt(VALUE);

        refusesNaming(sealed.replace(KEY_ID_1, KEY_ID_1.toUpperCase()), "no key id");
        refusesNaming(sealed.replace(KEY_ID_1 + ":", KEY_ID_1), "no key id");
        refusesNaming(sealed.replace(KEY_ID_1, KEY_ID_1.substring(1)), "no key id");
    }

    @Test
    public void needsResealTruthTable() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, null, true);
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertFalse("Null holds nothing to reseal", EncryptionUtils.needsReseal(null));
        assertTrue("An unmarked value", EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
        assertFalse("A value under the primary key", EncryptionUtils.needsReseal(underKey2));
        assertTrue("A value under a read-only key", EncryptionUtils.needsReseal(underKey1));
        assertTrue("A value under a key the ring does not hold", EncryptionUtils.needsReseal(underKey3));
        assertTrue("A marked value without a key id", EncryptionUtils.needsReseal("v2:AAAA"));

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.NO_KEY_TOKEN, true);
        assertTrue("An unmarked value once its reader is closed", EncryptionUtils.needsReseal(EARLIER_ENVELOPE));

        EncryptionUtils.initializeEncryptor(null, null, null, true);
        assertFalse("Without a key of the installation's own, a reseal writes the same format",
                EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
    }

    /**
     * The life of an installation that upgrades: the legacy reader opens the unmarked values beside a ring
     * that holds a read-only key, a reseal moves every value under the primary key, and the legacy reader
     * and the read-only key are then retired.
     */
    @Test
    public void unmarkedAndReadOnlyValuesAreResealedThenTheirReadersAreRetired() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
        assertTrue(EncryptionUtils.needsReseal(underKey1));

        String resealedEarlier =
                EncryptionUtils.passwordBaseEncrypt(EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
        String resealedUnderKey1 = EncryptionUtils.passwordBaseEncrypt(EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(resealedEarlier.startsWith("v2:" + KEY_ID_2 + ":"));
        assertTrue(resealedUnderKey1.startsWith("v2:" + KEY_ID_2 + ":"));
        assertFalse(EncryptionUtils.needsReseal(resealedEarlier));
        assertFalse(EncryptionUtils.needsReseal(resealedUnderKey1));

        EncryptionUtils.initializeEncryptor(KEY_2, emptyList(), null, EncryptionUtils.NO_KEY_TOKEN, true);
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(resealedEarlier));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(resealedUnderKey1));
        refusesNaming(EARLIER_ENVELOPE, EncryptionUtils.NO_KEY_TOKEN);
        refusesNaming(underKey1, KEY_ID_1);
        assertTrue("A value left behind is still counted", EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
    }

    @Test
    public void noneClosesTheReaderOfUnmarkedValues() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, EncryptionUtils.NO_KEY_TOKEN, true);
        String sealed = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealed));
        refusesNaming(EARLIER_ENVELOPE, EncryptionUtils.NO_KEY_TOKEN);
    }

    @Test
    public void noneReachesTheLegacyKeyThroughTheConfigurationToo() {
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.NO_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);

        refusesNaming(EARLIER_ENVELOPE, EncryptionUtils.NO_KEY_TOKEN);
    }

    @Test
    public void noneIsRefusedWithoutAKeyOfTheInstallationsOwn() {
        try {
            EncryptionUtils.initializeEncryptor(null, null, EncryptionUtils.NO_KEY_TOKEN, true);
            fail("Closing the only reader of the format new values are written in should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the property to set first, and got: " + e.getMessage(),
                    e.getMessage().contains(PASSWORD_PROP));
        }
    }

    @Test
    public void aTokenIsRefusedWhereAKeyIsExpected() {
        for (String token : asList(EncryptionUtils.NO_KEY_TOKEN, EncryptionUtils.SHIPPED_KEY_TOKEN)) {
            refusedAtInitialization(token, emptyList());
            refusedAtInitialization(KEY_1, singletonList(token));
        }
    }

    @Test
    public void thePrimaryKeyNamedAgainAsReadOnlyIsRefused() {
        refusedAtInitializationNaming(KEY_1, singletonList(KEY_1), "One key is named twice");
    }

    @Test
    public void aReadOnlyKeyNamedTwiceIsRefused() {
        refusedAtInitializationNaming(KEY_2, asList(KEY_1, KEY_3, KEY_1), "One key is named twice");
    }

    @Test
    public void aPassphraseAndTheKeyItDerivesNamedTogetherAreRefused() {
        refusedAtInitializationNaming(KEY_THE_PASSPHRASE_DERIVES, singletonList(PASSPHRASE),
                KEY_ID_OF_THE_PASSPHRASE);
    }

    @Test
    public void aNullOrBlankReadOnlyKeyIsRefusedNamingThePropertyOfReadOnlyKeys() {
        refusedAtInitializationNaming(KEY_1, singletonList(null), PREVIOUS_PROP);
        refusedAtInitializationNaming(KEY_1, singletonList("  "), PREVIOUS_PROP);
    }

    @Test(expected = IllegalArgumentException.class)
    public void theKeyIdOfNoSecretIsRefused() {
        EncryptionUtils.keyIdOf(null);
    }

    private static void refusedAtInitialization(String password, List<String> previous) {
        refusedAtInitializationNaming(password, previous, null);
    }

    private static void refusedAtInitializationNaming(String password, List<String> previous,
            String expected) {
        try {
            EncryptionUtils.initializeEncryptor(password, previous, null, null, true);
            fail("Expected the configuration to be refused");
        } catch (IllegalArgumentException e) {
            if (expected != null) {
                assertTrue("The message should name " + expected + ", and got: " + e.getMessage(),
                        e.getMessage().contains(expected));
            }
        }
    }

    private static void refusesNaming(String value, String expected) {
        try {
            String decrypted = EncryptionUtils.passwordBaseDecrypt(value);
            fail("Expected the value to be refused, and it read back as: " + decrypted);
        } catch (EncryptionOperationNotPossibleException e) {
            if (expected != null) {
                assertTrue("The message should name " + expected + ", and got: " + e.getMessage(),
                        e.getMessage() != null && e.getMessage().contains(expected));
            }
        }
    }
}
