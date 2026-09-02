package org.jahia.commons.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.After;
import org.junit.Test;

/**
 * Unit test for the two storage formats that {@link EncryptionUtils} reads, and for the one it writes.
 *
 * <p>The legacy format carries no marker, so a test cannot recognise it by inspection. Each test here produces a
 * legacy value through the configuration route that selects the legacy encryptor, which keeps this file independent
 * of the password the encryptor resolves.</p>
 */
public class VersionedEncryptionTest {

    private static final String MARKER = "{v2}";
    private static final String LEGACY_ALGORITHM = "PBEWithMD5AndDES";

    @After
    public void resetEncryptor() {
        EncryptionUtils.initializeEncryptor(null, null, true);
    }

    /** Produces a value in the legacy format, then restores the default configuration. */
    private String encryptAsLegacy(String plainText) {
        EncryptionUtils.initializeEncryptor(null, LEGACY_ALGORITHM, true);
        String legacyValue = EncryptionUtils.passwordBaseEncrypt(plainText);
        EncryptionUtils.initializeEncryptor(null, null, true);
        return legacyValue;
    }

    @Test
    public void shouldMarkANewValue() {
        EncryptionUtils.initializeEncryptor(null, null, true);

        String encrypted = EncryptionUtils.passwordBaseEncrypt("a-new-value");

        assertTrue("A new value carries the marker", encrypted.startsWith(MARKER));
    }

    @Test
    public void shouldReadBackANewValue() {
        EncryptionUtils.initializeEncryptor(null, null, true);
        String plainText = "round-trip-through-the-new-format";

        String encrypted = EncryptionUtils.passwordBaseEncrypt(plainText);

        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(encrypted));
    }

    @Test
    public void shouldGiveEveryValueItsOwnInitializationVector() {
        EncryptionUtils.initializeEncryptor(null, null, true);
        String plainText = "the-same-text-twice";

        String first = EncryptionUtils.passwordBaseEncrypt(plainText);
        String second = EncryptionUtils.passwordBaseEncrypt(plainText);

        assertNotEquals("Two values of the same text differ", first, second);
        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(first));
        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(second));
    }

    @Test
    public void shouldLeaveALegacyValueUnmarked() {
        String legacyValue = encryptAsLegacy("a-legacy-value");

        assertFalse("A legacy value carries no marker", legacyValue.startsWith(MARKER));
    }

    @Test
    public void shouldReadALegacyValueAfterAnUpgrade() {
        String plainText = "a-value-stored-by-an-earlier-version";
        String legacyValue = encryptAsLegacy(plainText);

        // The encryptor now writes the new format, and it still has to read the value above.
        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(legacyValue));
    }

    @Test
    public void shouldReadBothFormatsThroughOneEncryptor() {
        String legacyText = "stored-before-the-upgrade";
        String legacyValue = encryptAsLegacy(legacyText);

        String newText = "stored-after-the-upgrade";
        String newValue = EncryptionUtils.passwordBaseEncrypt(newText);

        assertFalse(legacyValue.startsWith(MARKER));
        assertTrue(newValue.startsWith(MARKER));
        assertEquals(legacyText, EncryptionUtils.passwordBaseDecrypt(legacyValue));
        assertEquals(newText, EncryptionUtils.passwordBaseDecrypt(newValue));
    }

    @Test
    public void shouldRefuseAChangedValue() {
        EncryptionUtils.initializeEncryptor(null, null, true);
        String encrypted = EncryptionUtils.passwordBaseEncrypt("a-value-someone-edits");

        // Change one character of the sealed body. AES-GCM authenticates the body, so the read has to fail.
        char[] body = encrypted.substring(MARKER.length()).toCharArray();
        int last = body.length - 1;
        body[last] = body[last] == 'A' ? 'B' : 'A';
        String changed = MARKER + new String(body);

        try {
            EncryptionUtils.passwordBaseDecrypt(changed);
            fail("A changed value has to be refused");
        } catch (EncryptionOperationNotPossibleException e) {
            // Expected. The cipher rejects a body that does not match its authentication tag.
        }
    }

    @Test
    public void shouldRefuseAShortValue() {
        EncryptionUtils.initializeEncryptor(null, null, true);

        try {
            EncryptionUtils.passwordBaseDecrypt(MARKER + "AAAA");
            fail("A value too short to hold a salt and an initialization vector has to be refused");
        } catch (EncryptionOperationNotPossibleException e) {
            // Expected.
        }
    }

    @Test
    public void shouldKeepAnAlgorithmTheOperatorNames() {
        EncryptionUtils.initializeEncryptor(null, LEGACY_ALGORITHM, true);
        String plainText = "the-operator-made-a-choice";

        String encrypted = EncryptionUtils.passwordBaseEncrypt(plainText);

        assertFalse("A named algorithm still writes its own format", encrypted.startsWith(MARKER));
        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(encrypted));
    }

    @Test
    public void shouldStillReadTheNewFormatWhenAnAlgorithmIsNamed() {
        EncryptionUtils.initializeEncryptor(null, null, true);
        String plainText = "written-before-the-operator-named-an-algorithm";
        String markedValue = EncryptionUtils.passwordBaseEncrypt(plainText);

        EncryptionUtils.initializeEncryptor(null, LEGACY_ALGORITHM, true);

        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(markedValue));
    }

    @Test
    public void shouldReportTheDefaultPasswordIsInUse() {
        EncryptionUtils.initializeEncryptor(null, null, true);

        assertTrue("No password is configured in this test run", EncryptionUtils.isUsingDefaultPassword());
    }

    @Test
    public void shouldReportAPasswordOfItsOwnIsInUse() {
        EncryptionUtils.initializeEncryptor("a-password-of-my-own", null, true);

        assertFalse("A password was given to the encryptor", EncryptionUtils.isUsingDefaultPassword());
    }

    @Test
    public void shouldReadBackAValueUnderAPasswordOfItsOwn() {
        EncryptionUtils.initializeEncryptor("a-password-of-my-own", null, true);
        String plainText = "encrypted-under-my-own-password";

        String encrypted = EncryptionUtils.passwordBaseEncrypt(plainText);

        assertTrue(encrypted.startsWith(MARKER));
        assertEquals(plainText, EncryptionUtils.passwordBaseDecrypt(encrypted));
    }

    @Test
    public void shouldRefuseAValueFromAnotherPassword() {
        EncryptionUtils.initializeEncryptor("the-first-password", null, true);
        String encrypted = EncryptionUtils.passwordBaseEncrypt("a-value-of-the-first-installation");

        EncryptionUtils.initializeEncryptor("the-second-password", null, true);

        try {
            EncryptionUtils.passwordBaseDecrypt(encrypted);
            fail("Another password has to fail to read the value");
        } catch (EncryptionOperationNotPossibleException e) {
            // Expected. The key of the second installation does not open the value of the first.
        }
    }
}
