package org.jahia.commons.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
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
