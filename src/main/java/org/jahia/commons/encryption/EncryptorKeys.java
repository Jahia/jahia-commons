package org.jahia.commons.encryption;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Every key an encryptor holds, named by an application that resolves its keys itself. The encryptor that
 * {@link EncryptionUtils#initializeEncryptor(EncryptorKeys, boolean)} builds from it reads no configuration:
 * a key left out here is a key the encryptor does not hold.
 *
 * <p>The legacy password is required, because a value carrying no format marker is read under it and no
 * default can name the right one for an application that resolves its own keys.</p>
 */
public final class EncryptorKeys {

    private final String password;
    private final String nextPassword;
    private final List<String> previousPasswords;
    private final String algorithm;
    private final String legacyPassword;

    private EncryptorKeys(Builder builder) {
        this.password = builder.password;
        this.nextPassword = builder.nextPassword;
        this.previousPasswords = builder.previousPasswords;
        this.algorithm = builder.algorithm;
        this.legacyPassword = builder.legacyPassword;
    }

    /**
     * @return a builder that names no key yet
     */
    public static Builder builder() {
        return new Builder();
    }

    String password() {
        return password;
    }

    String nextPassword() {
        return nextPassword;
    }

    List<String> previousPasswords() {
        return previousPasswords;
    }

    String algorithm() {
        return algorithm;
    }

    String legacyPassword() {
        return legacyPassword;
    }

    /**
     * Collects the keys of an encryptor. Each setter refuses a blank key, and {@link #build()} refuses a
     * missing legacy password.
     */
    public static final class Builder {

        private String password;
        private String nextPassword;
        private List<String> previousPasswords = Collections.emptyList();
        private String algorithm;
        private String legacyPassword;

        private Builder() {
        }

        /**
         * @param password the key that seals every new value, or null to name none, and then new values stay
         *            in the format carrying no marker, under the legacy password
         * @return this builder
         * @throws IllegalArgumentException if the key is blank
         */
        public Builder password(String password) {
            this.password = refuseBlank(password, "The password");
            return this;
        }

        /**
         * @param nextPassword the key about to seal new values, which opens values carrying the format marker
         *            and seals none, or null to name none
         * @return this builder
         * @throws IllegalArgumentException if the key is blank
         */
        public Builder nextPassword(String nextPassword) {
            this.nextPassword = refuseBlank(nextPassword, "The next password");
            return this;
        }

        /**
         * @param previousPasswords the keys that open values carrying the format marker, each found by the key
         *            id a value carries, or null or an empty list to name none
         * @return this builder
         * @throws IllegalArgumentException if one of the keys is null or blank
         */
        public Builder previousPasswords(List<String> previousPasswords) {
            if (previousPasswords == null) {
                this.previousPasswords = Collections.emptyList();
                return this;
            }
            List<String> keys = new ArrayList<>(previousPasswords.size());
            for (String previousPassword : previousPasswords) {
                if (previousPassword == null) {
                    throw new IllegalArgumentException("A previous password cannot be null.");
                }
                keys.add(refuseBlank(previousPassword, "A previous password"));
            }
            this.previousPasswords = Collections.unmodifiableList(keys);
            return this;
        }

        /**
         * @param algorithm the algorithm that reads a value carrying no format marker, or null for the jasypt
         *            default
         * @return this builder
         */
        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * @param legacyPassword the key that reads a value carrying no format marker:
         *            {@link EncryptionUtils#SHIPPED_KEY_TOKEN} for the password shipped with this library,
         *            {@link EncryptionUtils#NO_KEY_TOKEN} to refuse every such value, or the earlier password
         * @return this builder
         * @throws IllegalArgumentException if the key is blank
         */
        public Builder legacyPassword(String legacyPassword) {
            this.legacyPassword = refuseBlank(legacyPassword, "The legacy password");
            return this;
        }

        /**
         * @return the keys named so far
         * @throws IllegalArgumentException if no legacy password is named
         */
        public EncryptorKeys build() {
            if (legacyPassword == null) {
                throw new IllegalArgumentException("The legacy password is required. Name the password that wrote "
                        + "the values carrying no format marker: '" + EncryptionUtils.SHIPPED_KEY_TOKEN
                        + "' when none was set, the earlier password when one was, or '"
                        + EncryptionUtils.NO_KEY_TOKEN + "' when no such value is left.");
            }
            return new EncryptorKeys(this);
        }

        private static String refuseBlank(String key, String name) {
            if (key != null && key.trim().isEmpty()) {
                throw new IllegalArgumentException(name + " cannot be blank. Leave it out to name none.");
            }
            return key;
        }
    }
}
