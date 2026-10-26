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
    private static final String NEXT_PROP = "jahia-commons.encryptor.next";

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

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);
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
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey3));
    }

    /**
     * The rotation a passphrase is steered towards: a new primary key, and the earlier password as a
     * read-only key. Read-only keys open marked values only, so without a legacy password the unmarked values
     * would be read under the new primary key.
     */
    @Test
    public void readOnlyKeysWithoutALegacyPasswordAreRefused() {
        List<String> earlierPassword = singletonList(EARLIER_PASSWORD);
        try {
            EncryptionUtils.initializeEncryptor(KEY_2, earlierPassword, null, null, true);
            fail("Read-only keys without a legacy password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP));
        }

        System.setProperty(LEGACY_PASSWORD_PROP, EARLIER_PASSWORD);
        EncryptionUtils.initializeEncryptor(KEY_2, earlierPassword, null, null, true);
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

    @Test
    public void canDecryptTruthTable() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underKey3 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertTrue("Null", EncryptionUtils.canDecrypt(null));
        assertTrue("An unmarked value", EncryptionUtils.canDecrypt(EARLIER_ENVELOPE));
        assertTrue("A value under the primary key", EncryptionUtils.canDecrypt(underKey2));
        assertTrue("A value under a read-only key", EncryptionUtils.canDecrypt(underKey1));
        assertFalse("A value under a key the ring does not hold", EncryptionUtils.canDecrypt(underKey3));
        assertFalse("A marked value without a key id", EncryptionUtils.canDecrypt("v2:AAAA"));

        EncryptionUtils.initializeEncryptor(KEY_2, emptyList(), null, EncryptionUtils.NO_KEY_TOKEN, true);
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

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);
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

        EncryptionUtils.initializeEncryptor(KEY_2, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);
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
     * A cluster on the shipped key takes its first key in two rolling restarts, through the configuration as
     * an operator sets it: every node first holds the key as the next key, with the legacy password named,
     * then each node moves the key to the password and changes nothing else. A node at either step reads what
     * a node at the other step writes.
     */
    @Test
    public void aClusterTakesItsFirstKeyWithEveryNodeReadingTheOthers() {
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        System.setProperty(NEXT_PROP, KEY_1);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String fromAFirstStepNode = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertFalse("A node at the first step still writes the earlier format",
                fromAFirstStepNode.startsWith("v2:"));
        assertTrue(EncryptionUtils.isSealingInTheEarlierFormat());
        assertFalse("Nothing is resealed while no key seals", EncryptionUtils.needsReseal(fromAFirstStepNode));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));

        System.clearProperty(NEXT_PROP);
        System.setProperty(PASSWORD_PROP, KEY_1);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String fromAPromotedNode = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue(fromAPromotedNode.startsWith("v2:" + KEY_ID_1 + ":"));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(fromAFirstStepNode));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));

        // A node still at the first step, or rolled back to it.
        System.clearProperty(PASSWORD_PROP);
        System.setProperty(NEXT_PROP, KEY_1);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        assertTrue(EncryptionUtils.canDecrypt(fromAPromotedNode));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(fromAPromotedNode));
    }

    /**
     * The same two steps replace a key: the next key reads what a promoted node seals, and the promoted node
     * reads what the others still seal under the key it moved to the read-only keys.
     */
    @Test
    public void aClusterRotatesItsKeyThroughTheNextKey() {
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        System.setProperty(PASSWORD_PROP, KEY_1);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String beforeTheRotation = EncryptionUtils.passwordBaseEncrypt(VALUE);

        System.setProperty(NEXT_PROP, KEY_2);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String fromAFirstStepNode = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue("The next key seals nothing", fromAFirstStepNode.startsWith("v2:" + KEY_ID_1 + ":"));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));

        System.clearProperty(NEXT_PROP);
        System.setProperty(PASSWORD_PROP, KEY_2);
        System.setProperty(PREVIOUS_PROP + "1", KEY_1);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        String fromAPromotedNode = EncryptionUtils.passwordBaseEncrypt(VALUE);
        assertTrue(fromAPromotedNode.startsWith("v2:" + KEY_ID_2 + ":"));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(fromAFirstStepNode));
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(beforeTheRotation));
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));

        System.clearProperty(PREVIOUS_PROP + "1");
        System.setProperty(PASSWORD_PROP, KEY_1);
        System.setProperty(NEXT_PROP, KEY_2);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(fromAPromotedNode));
    }

    /**
     * Moving the key to the password would also move the default of the legacy key to it, so the legacy key
     * is named from the first step, by either route.
     */
    @Test
    public void aNextKeyWithoutALegacyPasswordIsRefused() {
        try {
            EncryptionUtils.initializeEncryptor(null, KEY_1, null, null, null, true);
            fail("A next key without a legacy password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP) && e.getMessage().contains(NEXT_PROP));
        }

        System.setProperty(NEXT_PROP, KEY_1);
        try {
            EncryptionUtils.initializeEncryptor(null, null, null, true);
            fail("A next key from the configuration without a legacy password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains(LEGACY_PASSWORD_PROP));
        }

        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(null, null, null, true);
        assertEquals(EARLIER_VALUE, EncryptionUtils.passwordBaseDecrypt(EARLIER_ENVELOPE));
    }

    @Test
    public void theNextKeyComesFromTheConfiguration() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        System.setProperty(NEXT_PROP, KEY_1);
        System.setProperty(LEGACY_PASSWORD_PROP, EncryptionUtils.SHIPPED_KEY_TOKEN);
        EncryptionUtils.initializeEncryptor(null, null, null, true);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
    }

    @Test
    public void theNextKeyNamedAsThePasswordIsRefusedWithThePromotion() {
        try {
            EncryptionUtils.initializeEncryptor(KEY_1, KEY_1, null, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
            fail("The next key named as the password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should say to remove the key from the next key, and got: " + e.getMessage(),
                    e.getMessage().contains("remove it from there") && e.getMessage().contains(NEXT_PROP));
        }
    }

    /**
     * A passphrase and the raw key it derives are one key, and the message names the move as it does for the
     * same secret written twice.
     */
    @Test
    public void theNextKeyDerivedFromThePasswordIsRefusedWithThePromotion() {
        try {
            EncryptionUtils.initializeEncryptor(PASSPHRASE, KEY_THE_PASSPHRASE_DERIVES, null, null,
                    EncryptionUtils.SHIPPED_KEY_TOKEN, true);
            fail("The next key derived from the password should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should name the key id and the move, and got: " + e.getMessage(),
                    e.getMessage().contains(KEY_ID_OF_THE_PASSPHRASE)
                            && e.getMessage().contains("remove it from there"));
        }
    }

    @Test
    public void aValueUnderAKeyTheRingLacksNamesWhereToAddIt() {
        EncryptionUtils.initializeEncryptor(KEY_2, null, null, true);
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        // With a primary key or without one, the missing key is either one the installation retired or one a
        // peer took, and the next key may already hold another.
        EncryptionUtils.initializeEncryptor(null, KEY_1, null, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
        refusesNaming(underKey2, PREVIOUS_PROP + "<n>, with " + LEGACY_PASSWORD_PROP);
        refusesNaming(underKey2, NEXT_PROP + " when the cluster is taking it");

        EncryptionUtils.initializeEncryptor(KEY_1, null, null, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
        refusesNaming(underKey2, PREVIOUS_PROP + "<n>, with " + LEGACY_PASSWORD_PROP);
        refusesNaming(underKey2, NEXT_PROP + " when the cluster is taking it");
    }

    /**
     * During a rotation, a node at the first step holds the new key as the next key, and a promoted peer seals
     * under it. A reseal on the first node would move those values back under the key the cluster is leaving.
     */
    @Test
    public void aValueUnderTheNextKeyNeedsNoReseal() {
        EncryptionUtils.initializeEncryptor(KEY_2, null, singletonList(KEY_1), null,
                EncryptionUtils.SHIPPED_KEY_TOKEN, true);
        String fromAPromotedNode = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_3, null, null, true);
        String underAnotherKey = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(KEY_1, KEY_2, null, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
        String fromAFirstStepNode = EncryptionUtils.passwordBaseEncrypt(VALUE);

        assertFalse("A value under the next key", EncryptionUtils.needsReseal(fromAPromotedNode));
        assertFalse("A value under the primary key", EncryptionUtils.needsReseal(fromAFirstStepNode));
        assertTrue("A value under another key", EncryptionUtils.needsReseal(underAnotherKey));
        assertTrue("An unmarked value", EncryptionUtils.needsReseal(EARLIER_ENVELOPE));
    }

    /**
     * Without a key that seals, '__none__' is refused, so the refusal of a missing legacy password does not offer
     * it, whichever keys that only open values are set.
     */
    @Test
    public void theRefusalOfAMissingLegacyPasswordOffersNoneOnlyWithAKeyThatSeals() {
        List<String> noReadOnlyKey = emptyList();
        List<String> aReadOnlyKey = singletonList(KEY_3);
        String none = EncryptionUtils.NO_KEY_TOKEN;
        assertFalse("A next key, no password", refusalOf(null, KEY_1, noReadOnlyKey).contains(none));
        assertFalse("A read-only key, no password", refusalOf(null, null, aReadOnlyKey).contains(none));
        assertFalse("Both, no password", refusalOf(null, KEY_1, aReadOnlyKey).contains(none));
        assertTrue("A next key and a password", refusalOf(KEY_2, KEY_1, noReadOnlyKey).contains(none));
        assertTrue("A read-only key and a password", refusalOf(KEY_2, null, aReadOnlyKey).contains(none));
    }

    private static String refusalOf(String password, String next, List<String> readOnlyKeys) {
        try {
            EncryptionUtils.initializeEncryptor(password, next, readOnlyKeys, null, null, true);
        } catch (IllegalArgumentException e) {
            assertTrue("The refusal should name the legacy password, and got: " + e.getMessage(),
                    e.getMessage().contains("Set " + LEGACY_PASSWORD_PROP + " now"));
            return e.getMessage();
        }
        fail("Keys that only open values, without a legacy password, should be refused");
        return null;
    }

    @Test
    public void theNextKeyNamedAsAReadOnlyKeyIsRefused() {
        List<String> readOnlyKeys = singletonList(KEY_1);
        try {
            EncryptionUtils.initializeEncryptor(KEY_2, KEY_1, readOnlyKeys, null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                    true);
            fail("One key named as the next key and as a read-only key should be refused");
        } catch (IllegalArgumentException e) {
            assertTrue("The message should say a key is named twice, and got: " + e.getMessage(),
                    e.getMessage().contains("named twice"));
        }
    }

    @Test
    public void aTokenOrABlankValueIsRefusedAsTheNextKey() {
        for (String notAKey : asList(EncryptionUtils.SHIPPED_KEY_TOKEN, EncryptionUtils.NO_KEY_TOKEN, " ")) {
            try {
                EncryptionUtils.initializeEncryptor(KEY_2, notAKey, null, null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                        true);
                fail("'" + notAKey + "' should be refused as the next key");
            } catch (IllegalArgumentException e) {
                assertTrue("The message should name the next key, and got: " + e.getMessage(),
                        e.getMessage().contains(NEXT_PROP));
            }
        }
    }

    /**
     * Read-only keys alone open what they name, as the next key does, and refuse every other key.
     */
    @Test
    public void readOnlyKeysAloneRefuseAValueUnderAnotherKey() {
        EncryptionUtils.initializeEncryptor(KEY_1, null, null, true);
        String underKey1 = EncryptionUtils.passwordBaseEncrypt(VALUE);
        EncryptionUtils.initializeEncryptor(KEY_2, null, null, true);
        String underKey2 = EncryptionUtils.passwordBaseEncrypt(VALUE);

        EncryptionUtils.initializeEncryptor(null, singletonList(KEY_1), null, EncryptionUtils.SHIPPED_KEY_TOKEN,
                true);

        assertEquals(VALUE, EncryptionUtils.passwordBaseDecrypt(underKey1));
        assertFalse(EncryptionUtils.canDecrypt(underKey2));
        refusesNaming(underKey2, KEY_ID_2);
        refusesNaming(underKey2, PREVIOUS_PROP + "<n>, with " + LEGACY_PASSWORD_PROP + " set, when this "
                + "installation retired that key, or to " + NEXT_PROP + " when the cluster is taking it");
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
            EncryptionUtils.initializeEncryptor(password, previous, null, EncryptionUtils.SHIPPED_KEY_TOKEN, true);
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
