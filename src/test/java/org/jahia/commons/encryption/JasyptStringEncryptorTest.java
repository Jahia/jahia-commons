package org.jahia.commons.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.NoSuchAlgorithmException;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.Test;

/**
 * Covers the reader of unmarked values: it reads what jasypt writes, and it refuses a read under another
 * key even when the block padding happens to check.
 */
public class JasyptStringEncryptorTest {

    private static final String ALGORITHM = "PBEWithMD5AndDES";
    private static final String VALUE = "a value long enough that random bytes do not read as UTF-8 text";

    @Test
    public void aValueJasyptWroteReadsBack() {
        StandardPBEStringEncryptor jasypt = new StandardPBEStringEncryptor();
        jasypt.setPassword("one-password");
        jasypt.setAlgorithm(ALGORITHM);

        assertEquals(VALUE, new JasyptStringEncryptor("one-password", ALGORITHM).decrypt(jasypt.encrypt(VALUE)));
        assertEquals("\u00e9t\u00e9 \ufffd", new JasyptStringEncryptor("one-password", ALGORITHM)
                .decrypt(jasypt.encrypt("\u00e9t\u00e9 \ufffd")));
    }

    /**
     * jasypt initializes on the first read, so an unknown algorithm surfaces there, and it reaches the caller
     * as a configuration error rather than as a refused value.
     */
    @Test
    public void anUnknownAlgorithmIsReportedAsAnInitializationError() {
        try {
            new JasyptStringEncryptor("one-password", "NoSuchAlg").decrypt("AAAAAAAAAAAAAAAAAAAAAA==");
            fail("An unknown algorithm should be reported");
        } catch (EncryptionInitializationException e) {
            assertTrue("The cause should be kept, and got: " + e.getCause(),
                    e.getCause() instanceof NoSuchAlgorithmException);
        }
    }

    @Test
    public void aValueThatIsNotBase64IsRefusedWithItsCause() {
        try {
            new JasyptStringEncryptor("one-password", ALGORITHM).decrypt("A");
            fail("A value that is not Base64 should be refused");
        } catch (EncryptionOperationNotPossibleException e) {
            assertTrue("The cause should be kept, and got: " + e.getCause(),
                    e.getCause() instanceof IllegalArgumentException);
        }
    }

    /**
     * About one read in 256 under another key passes the padding check. Across this many values, a lenient
     * decoder returns several of them as text.
     */
    @Test
    public void everyReadUnderAnotherKeyIsRefused() {
        JasyptStringEncryptor writer = new JasyptStringEncryptor("one-password", ALGORITHM);
        JasyptStringEncryptor otherKey = new JasyptStringEncryptor("another-password", ALGORITHM);
        for (int i = 0; i < 3000; i++) {
            String sealed = writer.encrypt(VALUE);
            try {
                String read = otherKey.decrypt(sealed);
                fail("A read under another key should be refused, and it returned: " + read);
            } catch (EncryptionOperationNotPossibleException e) {
                // refused, as every such read should be
            }
        }
    }
}
