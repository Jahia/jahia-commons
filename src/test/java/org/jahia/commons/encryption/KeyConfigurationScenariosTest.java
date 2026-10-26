package org.jahia.commons.encryption;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Covers every combination of the key settings against what an installation stores, then the procedures
 * that move an installation from one combination to the next. The expected outcome of each combination is
 * stated by {@link Setup} from the documented rules, independently of the code under test.
 */
public class KeyConfigurationScenariosTest {

    private static final String PASSWORD_PROP = "jahia-commons.encryptor.password";
    private static final String NEXT_PROP = "jahia-commons.encryptor.next";
    private static final String LEGACY_PASSWORD_PROP = "jahia-commons.encryptor.legacy.password";
    private static final String PREVIOUS_PROP = "jahia-commons.encryptor.previous.";

    private static final String KEY_0 = "base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final String KEY_1 = "base64:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final String KEY_2 = "base64:ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";
    private static final String KEY_ID_1 = "b0166dad948115e3";

    private static final String SHIPPED = EncryptionUtils.SHIPPED_KEY_TOKEN;
    private static final String NONE = EncryptionUtils.NO_KEY_TOKEN;
    // A password an installation set before it held a key of the marked format.
    private static final String OWN_PASSWORD = "site-owned-key";

    private static final String VALUE = "value-under-a-site-key";
    // Produced by jasypt 1.9.3 outside this codebase: one under the shipped password, one under OWN_PASSWORD.
    private static final String EARLIER_VALUE = "value-from-an-earlier-version";
    private static final String UNMARKED_UNDER_SHIPPED = "j+9rrpqFfEUdZiep6qzPj5Et7spc49pWmeG/3LbZZ5xxtWwQsj9NbA==";
    private static final String UNMARKED_WRITTEN_BY_THE_SITE = "7kcOkZ+19f6zRCgU6bo+c4JZa9UWfH6MmpnphkCHxTA=";

    private final Map<String, String> markedUnder = new LinkedHashMap<>();

    @Before
    public void sealAValueUnderEachKey() {
        clearConfiguration();
        for (String key : asList(KEY_0, KEY_1, KEY_2)) {
            EncryptionUtils.initializeEncryptor(key, null, null, true);
            markedUnder.put(key, EncryptionUtils.passwordBaseEncrypt(VALUE));
        }
        clearConfiguration();
    }

    @After
    public void clearConfiguration() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(NEXT_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        for (int n = 0; n <= 3; n++) {
            System.clearProperty(PREVIOUS_PROP + n);
        }
        EncryptionUtils.initializeEncryptor(null, null, null, true);
    }

    /**
     * The password unset, passed by the application, or read from the configuration; the next key unset or
     * set; a read-only key unset or set; the legacy password unset, the shipped token, a password of the
     * installation's own, or the token that closes its reader. 48 combinations.
     */
    @Test
    public void everyCombinationOfTheKeySettingsBehavesAsDocumented() {
        List<String> mismatches = new ArrayList<>();
        int combinations = 0;
        for (String password : asList(null, KEY_1)) {
            for (boolean passwordFromConfiguration : passwordFromConfiguration(password)) {
                for (String next : asList(null, KEY_2)) {
                    for (List<String> previous : asList(Collections.<String>emptyList(), singletonList(KEY_0))) {
                        for (String legacy : asList(null, SHIPPED, OWN_PASSWORD, NONE)) {
                            check(new Setup(password, passwordFromConfiguration, next, previous, legacy),
                                    mismatches);
                            combinations++;
                        }
                    }
                }
            }
        }
        assertEquals(48, combinations);
        assertTrue(mismatches.size() + " mismatches:\n" + String.join("\n", mismatches), mismatches.isEmpty());
    }

    /**
     * A cluster on the shipped key takes its first key: each step is one rolling restart.
     */
    @Test
    public void aFirstKeyFromTheShippedKeyTakesOneRestartPerStep() {
        assertOneRestartPerStep(asList(UNMARKED_UNDER_SHIPPED),
                new Setup(null, false, null, emptyList(), null),
                new Setup(null, false, KEY_1, emptyList(), null),
                new Setup(KEY_1, false, null, emptyList(), SHIPPED));
    }

    /**
     * An installation that set a password of its own before it held a key of the marked format takes its
     * first key.
     */
    @Test
    public void aFirstKeyOverAPasswordOfTheInstallationsOwnTakesOneRestartPerStep() {
        assertOneRestartPerStep(asList(UNMARKED_WRITTEN_BY_THE_SITE),
                new Setup(null, false, null, emptyList(), OWN_PASSWORD),
                new Setup(null, false, KEY_1, emptyList(), OWN_PASSWORD),
                new Setup(KEY_1, false, null, emptyList(), OWN_PASSWORD));
    }

    /**
     * The primary key is replaced, and the key it replaces stays readable.
     */
    @Test
    public void aRotationTakesOneRestartPerStep() {
        assertOneRestartPerStep(asList(UNMARKED_UNDER_SHIPPED, markedUnder.get(KEY_1)),
                new Setup(KEY_1, false, null, emptyList(), SHIPPED),
                new Setup(KEY_1, false, KEY_2, emptyList(), SHIPPED),
                new Setup(KEY_2, false, null, singletonList(KEY_1), SHIPPED));
    }

    /**
     * Once every value is sealed again under the primary key, the read-only key and then the reader of
     * unmarked values are retired, one rolling restart each.
     */
    @Test
    public void retiringTheEarlierKeysTakesOneRestartPerStep() {
        assertOneRestartPerStep(asList(markedUnder.get(KEY_2)),
                new Setup(KEY_2, false, null, singletonList(KEY_1), SHIPPED),
                new Setup(KEY_2, false, null, emptyList(), SHIPPED),
                new Setup(KEY_2, false, null, emptyList(), NONE));
    }

    private static List<Boolean> passwordFromConfiguration(String password) {
        return password == null ? singletonList(false) : asList(false, true);
    }

    private void check(Setup setup, List<String> mismatches) {
        boolean started = start(setup);
        if (started == setup.isRefused()) {
            mismatches.add(setup + ": expected " + (setup.isRefused() ? "a refusal" : "a start") + ", got the other");
            return;
        }
        if (!started) {
            return;
        }
        String written = EncryptionUtils.passwordBaseEncrypt(VALUE);
        boolean marked = written.startsWith("v2:");
        boolean sealing = setup.password != null;
        expect(mismatches, setup, "new values are marked", sealing, marked);
        expect(mismatches, setup, "a new value names the password",
                sealing, written.startsWith("v2:" + KEY_ID_1 + ":"));
        expect(mismatches, setup, "isSealingInTheEarlierFormat", !sealing,
                EncryptionUtils.isSealingInTheEarlierFormat());
        expect(mismatches, setup, "needsReseal of an unmarked value", sealing,
                EncryptionUtils.needsReseal(UNMARKED_UNDER_SHIPPED));

        expectRead(mismatches, setup, "unmarked under the shipped password", UNMARKED_UNDER_SHIPPED, EARLIER_VALUE,
                SHIPPED.equals(setup.legacyKey()), !NONE.equals(setup.legacyKey()));
        expectRead(mismatches, setup, "unmarked under the installation's own password", UNMARKED_WRITTEN_BY_THE_SITE,
                VALUE, OWN_PASSWORD.equals(setup.legacyKey()), !NONE.equals(setup.legacyKey()));
        for (Map.Entry<String, String> entry : markedUnder.entrySet()) {
            boolean held = setup.holds(entry.getKey());
            expectRead(mismatches, setup, "marked under " + name(entry.getKey()), entry.getValue(), VALUE, held,
                    held);
        }
        expectRead(mismatches, setup, "its own new value", written, VALUE, true, true);
        if (!marked) {
            // An unmarked value is written under the legacy key, so a node reading under that key alone reads it.
            start(new Setup(null, false, null, emptyList(), setup.legacyKey()));
            expectRead(mismatches, setup, "its new value, under the legacy key alone", written, VALUE, true, true);
        }
    }

    private void assertOneRestartPerStep(List<String> storedBefore, Setup... steps) {
        List<String> mismatches = new ArrayList<>();
        List<String> written = new ArrayList<>();
        for (Setup step : steps) {
            if (!start(step)) {
                mismatches.add(step + ": refused at startup");
                continue;
            }
            written.add(EncryptionUtils.passwordBaseEncrypt(VALUE));
        }
        for (int j = 0; j < steps.length && mismatches.isEmpty(); j++) {
            start(steps[j]);
            for (String stored : storedBefore) {
                expectReadable(mismatches, "step " + j + " reads a value stored before", stored);
            }
            // A node reads what nodes at every earlier step wrote, and what nodes one step ahead write, so it
            // runs beside them through the rolling restart of either step.
            for (int i = 0; i <= Math.min(j + 1, steps.length - 1); i++) {
                expectReadable(mismatches, "step " + j + " reads what step " + i + " wrote", written.get(i));
            }
        }
        assertTrue(String.join("\n", mismatches), mismatches.isEmpty());
    }

    private static boolean start(Setup setup) {
        System.clearProperty(PASSWORD_PROP);
        if (setup.passwordFromConfiguration) {
            System.setProperty(PASSWORD_PROP, setup.password);
        }
        try {
            EncryptionUtils.initializeEncryptor(setup.passwordFromConfiguration ? null : setup.password, setup.next,
                    setup.previous, null, setup.legacy, true);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void expect(List<String> mismatches, Setup setup, String what, boolean expected,
            boolean actual) {
        if (expected != actual) {
            mismatches.add(setup + ": " + what + " expected " + expected + ", got " + actual);
        }
    }

    private static void expectRead(List<String> mismatches, Setup setup, String what, String stored,
            String plain, boolean readable, boolean canDecrypt) {
        expect(mismatches, setup, "canDecrypt of a value " + what, canDecrypt, EncryptionUtils.canDecrypt(stored));
        String read = readOrNull(stored);
        if (readable ? !plain.equals(read) : read != null) {
            mismatches.add(setup + ": a value " + what + " expected " + (readable ? "read" : "refused") + ", got "
                    + (read == null ? "refused" : "'" + read + "'"));
        }
    }

    private static void expectReadable(List<String> mismatches, String what, String stored) {
        if (readOrNull(stored) == null) {
            mismatches.add(what + ": refused");
        }
    }

    private static String readOrNull(String stored) {
        try {
            return EncryptionUtils.passwordBaseDecrypt(stored);
        } catch (EncryptionOperationNotPossibleException e) {
            return null;
        }
    }

    private static String name(String key) {
        return KEY_0.equals(key) ? "KEY_0" : KEY_1.equals(key) ? "KEY_1" : KEY_2.equals(key) ? "KEY_2" : key;
    }

    /**
     * One combination of the key settings, and what the documentation says it does.
     */
    private static final class Setup {

        private final String password;
        private final boolean passwordFromConfiguration;
        private final String next;
        private final List<String> previous;
        private final String legacy;

        Setup(String password, boolean passwordFromConfiguration, String next, List<String> previous,
                String legacy) {
            this.password = password;
            this.passwordFromConfiguration = passwordFromConfiguration;
            this.next = next;
            this.previous = previous;
            this.legacy = legacy;
        }

        /**
         * Read-only keys need a named legacy password, and closing its reader needs a key that seals. The next
         * key needs neither.
         */
        boolean isRefused() {
            return (!previous.isEmpty() && legacy == null) || (NONE.equals(legacy) && password == null);
        }

        /**
         * The legacy password when named. Otherwise the password read from the configuration, which wrote the
         * unmarked values before this version, and the shipped password when none was configured.
         */
        String legacyKey() {
            if (legacy != null) {
                return legacy;
            }
            return passwordFromConfiguration ? password : SHIPPED;
        }

        boolean holds(String key) {
            return key.equals(password) || key.equals(next) || previous.contains(key);
        }

        @Override
        public String toString() {
            return "[password=" + (password == null ? "-" : name(password) + (passwordFromConfiguration
                    ? " (configuration)" : " (argument)")) + ", next=" + (next == null ? "-" : name(next))
                    + ", previous=" + (previous.isEmpty() ? "-" : name(previous.get(0))) + ", legacy="
                    + (legacy == null ? "-" : OWN_PASSWORD.equals(legacy) ? "own" : legacy) + "]";
        }
    }
}
