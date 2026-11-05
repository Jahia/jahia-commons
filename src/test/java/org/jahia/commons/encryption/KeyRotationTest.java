package org.jahia.commons.encryption;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
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
    private static final String NEXT_PROP = "jahia-commons.encryptor.next";
    private static final String LEGACY_ALGORITHM_PROP = "jahia-commons.encryptor.legacy.algorithm";

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
    // Produced the same way, under a password an installation set before it held a key of the marked format.
    private static final String EARLIER_PASSWORD = "site-owned-key";
    private static final String UNDER_EARLIER_PASSWORD = "7kcOkZ+19f6zRCgU6bo+c4JZa9UWfH6MmpnphkCHxTA=";

    @Before
    public void clearConfiguration() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        System.clearProperty(NEXT_PROP);
        System.clearProperty(LEGACY_ALGORITHM_PROP);
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

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(EncryptionUtils.needsReseal(underKey1));
        String resealed = EncryptionUtils.passwordBaseEncrypt(EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertTrue(resealed.startsWith("v2:" + KEY_ID_2 + ":"));
        assertFalse(EncryptionUtils.needsReseal(resealed));

        initialize(keys(KEY_2));
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
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey3));
    }

    /**
     * The rotation a passphrase is steered towards: a new primary key, and the earlier password as a
     * read-only key. Read-only keys open marked values only, so the unmarked values are read under the legacy
     * password.
     */
    @Test
    public void readOnlyKeysBesideALegacyPasswordReadTheUnmarkedValuesUnderIt() {
        initialize(keys(KEY_2).previousPasswords(singletonList(EARLIER_PASSWORD)).legacyPassword(EARLIER_PASSWORD));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(UNDER_EARLIER_PASSWORD));
    }

    @Test
    public void readOnlyKeysFromTheConfigurationWithoutALegacyPasswordAreRefused() {
        System.setProperty(PASSWORD_PROP, KEY_2);
        System.setProperty(PREVIOUS_PROP + "1", EARLIER_PASSWORD);
        try {
            EncryptionUtils.initializeEncryptor(null, null, null, true);
            fail("Read-only keys without a legacy password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP));
        }
    }

    /**
     * A cluster on the shipped key sets its first key: every node names it as the next key, then each node
     * makes it the primary key. A node still on the first step reads what a promoted node seals, and a node
     * rolled back from the second step returns to the first.
     */
    @Test
    public void aFirstKeyRollsOutThroughTheNextKey() {
        initialize(keys(null).nextPassword(KEY_1));
        String sealedOnTheFirstStep = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertFalse("New values stay in the earlier format", sealedOnTheFirstStep.startsWith("v2:"));
        assertTrue(EncryptionUtils.isSealingInTheEarlierFormat());
        assertFalse("A reseal would write the same format", EncryptionUtils.needsReseal(sealedOnTheFirstStep));

        initialize(keys(KEY_1));
        String sealedOnTheSecondStep = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue(sealedOnTheSecondStep.startsWith("v2:" + KEY_ID_1 + ":"));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealedOnTheFirstStep));
        assertTrue(EncryptionUtils.needsReseal(sealedOnTheFirstStep));

        initialize(keys(null).nextPassword(KEY_1));
        assertTrue(EncryptionUtils.canDecrypt(sealedOnTheSecondStep));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealedOnTheSecondStep));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealedOnTheFirstStep));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    @Test
    public void aRotationRollsOutThroughTheNextKey() {
        initialize(keys(KEY_1).nextPassword(KEY_2));
        String sealedOnTheFirstStep = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue(sealedOnTheFirstStep.startsWith("v2:" + KEY_ID_1 + ":"));

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
        String sealedOnTheSecondStep = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue(sealedOnTheSecondStep.startsWith("v2:" + KEY_ID_2 + ":"));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealedOnTheFirstStep));

        initialize(keys(KEY_1).nextPassword(KEY_2));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(sealedOnTheSecondStep));
        assertFalse("A reseal here would move the value back under the key being retired",
                EncryptionUtils.needsReseal(sealedOnTheSecondStep));
        assertFalse(EncryptionUtils.needsReseal(sealedOnTheFirstStep));
    }

    @Test
    public void theNextKeyComesFromTheConfiguration() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        System.setProperty(NEXT_PROP, KEY_1);
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertTrue(EncryptionUtils.isSealingInTheEarlierFormat());
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
    }

    /**
     * The keys an application names are every key the encryptor holds: the keys left in the configuration
     * are not read, and the configured legacy password and algorithm give way to the ones named.
     */
    @Test
    public void theKeysOfAnApplicationLeaveTheConfigurationUnread() {
        EncryptionUtils.initializeEncryptor(KEY_2, null, null, true);
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        System.setProperty(NEXT_PROP, KEY_2);
        System.setProperty(PREVIOUS_PROP + "1", KEY_3);
        System.setProperty(PASSWORD_PROP, KEY_3);
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.NO_KEY_TOKEN);
        System.setProperty(LEGACY_ALGORITHM_PROP, "PBEWithMD5AndTripleDES");

        initialize(keys(KEY_1));

        assertFalse(EncryptionUtils.isSealingInTheEarlierFormat());
        assertTrue(EncryptionUtils.passwordBaseEncrypt(VALUE).startsWith("v2:" + KEY_ID_1 + ":"));
        refusesNaming(underKey2, KEY_ID_2);
        refusesNaming(underKey3, EncryptionUtils.keyIdOf(KEY_3));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    /** A node whose next key became its primary key names no next key, and the configuration does not bring it back. */
    @Test
    public void theKeysOfAnApplicationLeaveAConfiguredNextKeyOutOfTheRing() {
        System.setProperty(NEXT_PROP, KEY_1);

        initialize(keys(KEY_1));

        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
    }

    @Test
    public void theKeysOfAnApplicationWithoutAPrimaryKeyLeaveAConfiguredNextKeyUnread() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        System.setProperty(NEXT_PROP, KEY_1);

        initialize(keys(null));

        assertTrue(EncryptionUtils.isSealingInTheEarlierFormat());
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
        refusesNaming(underKey1, "no key for that format");
    }

    @Test
    public void theRefusalsOfAValueNameEachKeyOfAnApplicationByItsRole() {
        initialize(keys(KEY_1));
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        initialize(keys(KEY_2));
        assertEquals("The value was sealed under the key with id " + KEY_ID_1 + ", and this installation holds "
                + "no such key. Add that key as a read-only key, or as the next key when it is about to seal new "
                + "values, to read the value.", refusalOf(underKey1));

        initialize(keys(null));
        assertTrue(refusalOf(underKey1).endsWith("Set the next key to the key the value was sealed with, or the "
                + "password once every node holds it."));

        initialize(EncryptorKeys.builder().password(KEY_1).legacyPassword(EARLIER_PASSWORD));
        assertTrue(refusalOf(EARLIER_ENVELOPE).contains("Set the legacy password to the password that wrote it"));
    }

    @Test
    public void theRefusalsOfAValueNameEachConfiguredKeyByItsProperty() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
        assertTrue(refusalOf(underKey1).contains("Add that key to " + PREVIOUS_PROP + "<n>, or to " + NEXT_PROP
                + " when it is about to seal new values"));

        EncryptionUtils.initializeEncryptor(KEY_1, null, EARLIER_PASSWORD, true);
        assertTrue(refusalOf(EARLIER_ENVELOPE).contains("Set " + LEGACY_PASSWORD_PROP + " to the password"));
    }

    @Test
    public void theLegacyPasswordIsRequired() {
        EncryptorKeys.Builder keys = EncryptorKeys.builder().password(KEY_1).nextPassword(KEY_2);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, keys::build);
        assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                e.getMessage().startsWith("The legacy password is required"));
    }

    @Test
    public void aBlankKeyIsRefusedNamingIt() {
        for (String blank : asList("", "  ")) {
            refusedByTheBuilderNaming(() -> EncryptorKeys.builder().password(blank), "The password cannot be blank");
            refusedByTheBuilderNaming(() -> EncryptorKeys.builder().nextPassword(blank),
                    "The next key cannot be blank");
            refusedByTheBuilderNaming(() -> EncryptorKeys.builder().legacyPassword(blank),
                    "The legacy password cannot be blank");
            refusedByTheBuilderNaming(() -> EncryptorKeys.builder().previousPasswords(singletonList(blank)),
                    "A read-only key cannot be blank");
        }
        refusedByTheBuilderNaming(() -> EncryptorKeys.builder().previousPasswords(singletonList(null)),
                "A read-only key cannot be null");
    }

    @Test
    public void aValueUnderAKeyOtherThanTheNextOneIsRefusedWithoutAPrimaryKey() {
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        initialize(keys(null).nextPassword(KEY_1));

        assertFalse(EncryptionUtils.canDecrypt(underKey3));
        refusesNaming(underKey3, EncryptionUtils.keyIdOf(KEY_3));
    }

    /**
     * The legacy key follows the encryption password unless it is named, so promoting the next key would read
     * every unmarked value under it.
     */
    @Test
    public void theNextKeyFromTheConfigurationWithoutALegacyPasswordIsRefused() {
        System.setProperty(NEXT_PROP, KEY_2);
        try {
            EncryptionUtils.initializeEncryptor(null, null, null, true);
            fail("A next key without a legacy password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP));
        }
    }

    @Test
    public void theNextKeyLeftBesideThePrimaryKeyItBecameIsRefusedNamingThePromotion() {
        refusedWithNextKeyNaming(KEY_1, KEY_1, emptyList(), "promoted");
        refusedWithNextKeyNaming(KEY_THE_PASSPHRASE_DERIVES, PASSPHRASE, emptyList(), "promoted");
    }

    /**
     * A read-only key that collides by key id with the next key, not with the primary key, is a key named
     * twice and not a promotion.
     */
    @Test
    public void aReadOnlyKeyDerivedFromTheNextPassphraseIsRefusedAsNamedTwice() {
        List<String> previous = singletonList(KEY_THE_PASSPHRASE_DERIVES);
        EncryptorKeys.Builder refused = keys(KEY_1).nextPassword(PASSPHRASE).previousPasswords(previous);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
        assertTrue("The message should say named twice, and got: " + e.getMessage(),
                e.getMessage().contains(KEY_ID_OF_THE_PASSPHRASE + " is named twice"));
        assertFalse("The message should not name a promotion, and got: " + e.getMessage(),
                e.getMessage().contains("promoted"));
    }

    @Test
    public void theNextKeyNamedAgainAsReadOnlyIsRefused() {
        refusedWithNextKeyNaming(KEY_2, KEY_1, singletonList(KEY_1), "One key is named twice");
    }

    @Test
    public void aTokenIsRefusedAsTheNextKey() {
        for (String token : asList(EncryptionUtils.NO_KEY_TOKEN, EncryptionUtils.SHIPPED_KEY_TOKEN)) {
            refusedWithNextKeyNaming(KEY_1, token, emptyList(), "the next key takes a key");
            refusedWithNextKeyNaming(null, token, emptyList(), "the next key takes a key");
        }
    }

    @Test
    public void aTokenSetAsTheNextKeyIsRefusedNamingItsProperty() {
        System.setProperty(NEXT_PROP, EncryptionUtils.NO_KEY_TOKEN);
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        try {
            EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
            fail("A token as the next key should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the property, and got: " + e.getMessage(),
                    e.getMessage().contains(NEXT_PROP + " takes a key"));
        }
    }

    @Test
    public void theNextKeySetBesideThePasswordItBecameIsRefusedNamingTheProperties() {
        System.setProperty(PASSWORD_PROP, KEY_1);
        System.setProperty(NEXT_PROP, KEY_1);
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        try {
            EncryptionUtils.initializeEncryptor(null, null, null, true);
            fail("The next key beside the password it became should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name both properties, and got: " + e.getMessage(),
                    e.getMessage().contains(NEXT_PROP) && e.getMessage().contains(PASSWORD_PROP));
        }
    }

    /**
     * An application that passes its keys names its settings itself, so a refusal of its keys names each key by
     * its role, and no property of this library.
     */
    @Test
    public void theRefusalsOfTheKeysOfAnApplicationNameNoProperty() {
        List<EncryptorKeys.Builder> refusedKeys = asList(
                keys(KEY_1).nextPassword(EncryptionUtils.NO_KEY_TOKEN),
                keys(EncryptionUtils.SHIPPED_KEY_TOKEN),
                keys(KEY_1).previousPasswords(singletonList(EncryptionUtils.NO_KEY_TOKEN)),
                keys(KEY_1).nextPassword(KEY_1),
                keys(KEY_1).previousPasswords(singletonList(KEY_1)),
                keys(KEY_THE_PASSPHRASE_DERIVES).previousPasswords(singletonList(PASSPHRASE)),
                keys(null).nextPassword(KEY_1).legacyPassword(EncryptionUtils.NO_KEY_TOKEN));
        for (EncryptorKeys.Builder refused : refusedKeys) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
            assertFalse("The message should name no property, and got: " + e.getMessage(),
                    e.getMessage().contains("jahia-commons.encryptor."));
        }
    }

    @Test
    public void noneIsRefusedWithTheNextKeyAlone() {
        EncryptorKeys.Builder refused = keys(null).nextPassword(KEY_1).legacyPassword(EncryptionUtils.NO_KEY_TOKEN);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
        assertTrue("The message should name the key to set first, and got: " + e.getMessage(),
                e.getMessage().contains("until the password names a key"));
    }

    /**
     * An installation that ran on the shipped key, and whose legacy key follows a password it set later,
     * reads its earlier values under the wrong key. The refusal names the property to fix, and neither the
     * value nor a key.
     */
    @Test
    public void anUnmarkedValueUnderAnotherLegacyKeyIsRefusedNamingTheLegacyPassword() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, EARLIER_PASSWORD, true);
        try {
            String decrypted = EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE);
            fail("Expected the value to be refused, and it read back as: " + decrypted);
        } catch (EncryptionOperationNotPossibleException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage() != null && e.getMessage().contains(LEGACY_PASSWORD_PROP));
            assertNotNull("The cause should be kept", e.getCause());
            assertFalse("The message should name no key, and got: " + e.getMessage(),
                    e.getMessage().contains(EARLIER_PASSWORD) || e.getMessage().contains(KEY_1)
                            || e.getMessage().contains(EARLIER_ENVELOPE));
        }
    }

    @Test
    public void canDecryptTruthTable() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertTrue("Null", EncryptionUtils.canDecrypt(null));
        assertTrue("An unmarked value", EncryptionUtils.canDecrypt(EARLIER_ENVELOPE));
        assertTrue("A value under the primary key", EncryptionUtils.canDecrypt(underKey2));
        assertTrue("A value under a read-only key", EncryptionUtils.canDecrypt(underKey1));
        assertFalse("A value under a key the ring does not hold", EncryptionUtils.canDecrypt(underKey3));
        assertFalse("A marked value without a key id", EncryptionUtils.canDecrypt("v2:AAAA"));

        initialize(keys(KEY_2).legacyPassword(EncryptionUtils.NO_KEY_TOKEN));
        assertFalse("An unmarked value once its reader is closed", EncryptionUtils.canDecrypt(EARLIER_ENVELOPE));
        assertFalse("A value under a key dropped from the ring", EncryptionUtils.canDecrypt(underKey1));

        EncryptionUtils.initializeEncryptor(null, null, null, true);
        assertFalse("A marked value without a key of the installation's own", EncryptionUtils.canDecrypt(underKey2));
        assertTrue("An unmarked value under the shipped password", EncryptionUtils.canDecrypt(EARLIER_ENVELOPE));
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

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
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

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertFalse("Null holds nothing to reseal", EncryptionUtils.needsReseal(null));
        assertTrue("An unmarked value", EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
        assertFalse("A value under the primary key", EncryptionUtils.needsReseal(underKey2));
        assertTrue("A value under a read-only key", EncryptionUtils.needsReseal(underKey1));
        assertTrue("A value under a key the ring does not hold", EncryptionUtils.needsReseal(underKey3));
        assertTrue("A marked value without a key id", EncryptionUtils.needsReseal("v2:AAAA"));

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)).legacyPassword(EncryptionUtils.NO_KEY_TOKEN));
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

        initialize(keys(KEY_2).previousPasswords(singletonList(KEY_1)));
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

        initialize(keys(KEY_2).legacyPassword(EncryptionUtils.NO_KEY_TOKEN));
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

    /**
     * A read-only key that collides with the primary key by key id is a key named twice, not a promotion.
     */
    @Test
    public void aReadOnlyKeyDerivedFromThePrimaryPassphraseIsRefusedAsNamedTwice() {
        List<String> previous = singletonList(KEY_THE_PASSPHRASE_DERIVES);
        EncryptorKeys.Builder refused = keys(PASSPHRASE).previousPasswords(previous);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
        assertTrue("The message should say named twice, and got: " + e.getMessage(),
                e.getMessage().contains(KEY_ID_OF_THE_PASSPHRASE + " is named twice"));
        assertFalse("The message should not name a promotion, and got: " + e.getMessage(),
                e.getMessage().contains("promoted"));
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
        EncryptorKeys.Builder refused = keys(password).previousPasswords(previous);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
        if (expected != null) {
            assertTrue("The message should name " + expected + ", and got: " + e.getMessage(),
                    e.getMessage().contains(expected));
        }
    }

    private static void refusedWithNextKeyNaming(String password, String next, List<String> previous,
            String expected) {
        EncryptorKeys.Builder refused = keys(password).nextPassword(next).previousPasswords(previous);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> initialize(refused));
        assertTrue("The message should name " + expected + ", and got: " + e.getMessage(),
                e.getMessage().contains(expected));
    }

    /** The keys every value here is read under, with the shipped password reading the unmarked ones. */
    private static EncryptorKeys.Builder keys(String password) {
        return EncryptorKeys.builder().password(password).legacyPassword(EncryptionUtils.SHIPPED_KEY_TOKEN);
    }

    private static void initialize(EncryptorKeys.Builder keys) {
        EncryptionUtils.initializeEncryptor(keys.build(), true);
    }

    private static void refusedByTheBuilderNaming(Runnable naming, String expected) {
        try {
            naming.run();
            fail("Expected the key to be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should start with " + expected + ", and got: " + e.getMessage(),
                    e.getMessage().startsWith(expected));
        }
    }

    private static String refusalOf(String value) {
        return assertThrows(EncryptionOperationNotPossibleException.class,
                () -> EncryptionUtils.passwordBaseDecrypt(value)).getMessage();
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
