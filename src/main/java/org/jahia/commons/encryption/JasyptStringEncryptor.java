package org.jahia.commons.encryption;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * Reads and writes the unmarked value format, as jasypt's {@link StandardPBEStringEncryptor} does, and
 * decodes what it reads as strict UTF-8.
 *
 * <p>The format checks nothing but the block padding, so a read under another key passes that check about
 * once in 256 values. Strict decoding refuses nearly every such read, where a lenient decoder returns
 * replacement characters as if they were the value.</p>
 */
final class JasyptStringEncryptor implements StringEncryptor {

    private final StandardPBEStringEncryptor writer = new StandardPBEStringEncryptor();
    private final StandardPBEByteEncryptor reader = new StandardPBEByteEncryptor();

    JasyptStringEncryptor(String password, String algorithm) {
        writer.setPassword(password);
        writer.setAlgorithm(algorithm);
        reader.setPassword(password);
        reader.setAlgorithm(algorithm);
    }

    @Override
    public String encrypt(String message) {
        return writer.encrypt(message);
    }

    // The steps of StandardPBEStringEncryptor.decrypt, with a strict decoder at the end. Its Base64 decoder
    // skips characters outside the alphabet, as the MIME decoder does.
    @Override
    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }
        byte[] plain;
        try {
            byte[] sealed = Base64.getMimeDecoder().decode(encryptedMessage.getBytes(StandardCharsets.US_ASCII));
            plain = reader.decrypt(sealed);
        } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException e) {
            // The byte encryptor initializes on its first decrypt, so a configuration error, such as an
            // unknown legacy algorithm, surfaces here.
            throw e;
        } catch (RuntimeException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(plain)).toString();
        } catch (CharacterCodingException e) {
            throw new EncryptionOperationNotPossibleException("The value carries no format marker, and it does "
                    + "not read as text under jahia-commons.encryptor.legacy.password, so another key wrote it.");
        }
    }
}
