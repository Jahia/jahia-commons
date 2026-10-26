package org.jahia.commons.encryption;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
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

    /** How a setting reaches the library: passed by the application, or read from the configuration. */
    private enum Route { ARGUMENT, CONFIGURATION }

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
        clearProperties();
        EncryptionUtils.initializeEncryptor(null, null, null, true);
    }

    /**
     * The password, the next key and a read-only key, each unset, passed by the application, or read from
     * the configuration; the legacy password unset, or the shipped token, a password of the installation's
     * own, or the token that closes its reader, by either route. 189 combinations.
     */
    @Test
    public void everyCombinationOfTheKeySettingsBehavesAsDocumented() {
        List<String> mismatches = new ArrayList<>();
        int combinations = 0;
        for (Setup password : routes(Setup.nothing(), (setup, route) -> setup.password(KEY_1, route))) {
            for (Setup next : routes(password, (setup, route) -> setup.next(KEY_2, route))) {
                for (Setup previous : routes(next, (setup, route) -> setup.previous(KEY_0, route))) {
                    List<Setup> legacies = new ArrayList<>(singletonList(previous));
                    for (String legacy : asList(SHIPPED, OWN_PASSWORD, NONE)) {
                        for (Route route : Route.values()) {
                            legacies.add(previous.legacy(legacy, route));
                        }
                    }
                    for (Setup setup : legacies) {
                        check(setup, mismatches);
                        combinations++;
                    }
                }
            }
        }
        assertEquals(189, combinations);
        assertTrue(mismatches.size() + " mismatches:\n" + String.join("\n", mismatches), mismatches.isEmpty());
    }

    /**
     * A cluster on the shipped key takes its first key: the first step sets the next key and names the legacy
     * password, and the second one only moves the key to the password.
     */
    @Test
    public void aFirstKeyFromTheShippedKeyTakesOneRestartPerStep() {
        Setup named = Setup.nothing().legacy(SHIPPED, Route.CONFIGURATION);
        assertOneRestartPerStep(asList(UNMARKED_UNDER_SHIPPED),
                Setup.nothing(),
                named.next(KEY_1, Route.CONFIGURATION),
                named.password(KEY_1, Route.CONFIGURATION));
    }

    /**
     * A site on version 1.1.0 holds its own passphrase in the password, and the unmarked values it wrote under
     * it. The upgrade makes the passphrase the primary key at once, and a rotation then replaces it.
     */
    @Test
    public void aSiteWithItsOwnPassphraseUpgradesThenRotatesOneRestartPerStep() {
        assertOneRestartPerStep(asList(UNMARKED_WRITTEN_BY_THE_SITE),
                Setup.nothing().password(OWN_PASSWORD, Route.CONFIGURATION),
                Setup.nothing().password(OWN_PASSWORD, Route.CONFIGURATION).next(KEY_2, Route.CONFIGURATION)
                        .legacy(OWN_PASSWORD, Route.CONFIGURATION),
                Setup.nothing().password(KEY_2, Route.CONFIGURATION).previous(OWN_PASSWORD, Route.CONFIGURATION)
                        .legacy(OWN_PASSWORD, Route.CONFIGURATION));
    }

    /**
     * The primary key is replaced, and the key it replaces stays readable.
     */
    @Test
    public void aRotationTakesOneRestartPerStep() {
        Setup named = Setup.nothing().legacy(SHIPPED, Route.CONFIGURATION);
        assertOneRestartPerStep(asList(UNMARKED_UNDER_SHIPPED, markedUnder.get(KEY_1)),
                named.password(KEY_1, Route.CONFIGURATION),
                named.password(KEY_1, Route.CONFIGURATION).next(KEY_2, Route.CONFIGURATION),
                named.password(KEY_2, Route.CONFIGURATION).previous(KEY_1, Route.CONFIGURATION));
    }

    /**
     * Once every value is sealed again under the primary key, the read-only key and then the reader of
     * unmarked values are retired, one rolling restart each.
     */
    @Test
    public void retiringTheEarlierKeysTakesOneRestartPerStep() {
        Setup sealing = Setup.nothing().password(KEY_2, Route.CONFIGURATION);
        assertOneRestartPerStep(asList(markedUnder.get(KEY_2)),
                sealing.previous(KEY_1, Route.CONFIGURATION).legacy(SHIPPED, Route.CONFIGURATION),
                sealing.legacy(SHIPPED, Route.CONFIGURATION),
                sealing.legacy(NONE, Route.CONFIGURATION));
    }

    private interface Adding {
        Setup add(Setup setup, Route route);
    }

    private static List<Setup> routes(Setup without, Adding adding) {
        return asList(without, adding.add(without, Route.ARGUMENT), adding.add(without, Route.CONFIGURATION));
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
            start(Setup.nothing().legacy(setup.legacyKey(), Route.ARGUMENT));
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
            // A reseal at one step must not move what the next step wrote back under the key it is leaving.
            if (j + 1 < steps.length && EncryptionUtils.needsReseal(written.get(j + 1))) {
                mismatches.add("step " + j + " reports what step " + (j + 1) + " wrote as needing a reseal");
            }
        }
        assertTrue(String.join("\n", mismatches), mismatches.isEmpty());
    }

    private static void clearProperties() {
        System.clearProperty(PASSWORD_PROP);
        System.clearProperty(NEXT_PROP);
        System.clearProperty(LEGACY_PASSWORD_PROP);
        for (int n = 0; n <= 3; n++) {
            System.clearProperty(PREVIOUS_PROP + n);
        }
    }

    private static boolean start(Setup setup) {
        clearProperties();
        if (setup.passwordRoute == Route.CONFIGURATION) {
            System.setProperty(PASSWORD_PROP, setup.password);
        }
        if (setup.nextRoute == Route.CONFIGURATION) {
            System.setProperty(NEXT_PROP, setup.next);
        }
        if (setup.previousRoute == Route.CONFIGURATION) {
            System.setProperty(PREVIOUS_PROP + "1", setup.previous.get(0));
        }
        if (setup.legacyRoute == Route.CONFIGURATION) {
            System.setProperty(LEGACY_PASSWORD_PROP, setup.legacy);
        }
        List<String> previous = setup.previous.isEmpty() ? emptyList()
                : setup.previousRoute == Route.ARGUMENT ? setup.previous : null;
        try {
            EncryptionUtils.initializeEncryptor(argument(setup.password, setup.passwordRoute),
                    argument(setup.next, setup.nextRoute), previous, null, argument(setup.legacy, setup.legacyRoute),
                    true);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String argument(String value, Route route) {
        return route == Route.ARGUMENT ? value : null;
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
        if (KEY_0.equals(key)) {
            return "KEY_0";
        }
        if (KEY_1.equals(key)) {
            return "KEY_1";
        }
        if (KEY_2.equals(key)) {
            return "KEY_2";
        }
        return OWN_PASSWORD.equals(key) ? "own" : key;
    }

    /**
     * One combination of the key settings, each with the route it reaches the library by, and what the
     * documentation says it does.
     */
    private static final class Setup {

        private String password;
        private Route passwordRoute;
        private String next;
        private Route nextRoute;
        private List<String> previous = emptyList();
        private Route previousRoute;
        private String legacy;
        private Route legacyRoute;

        static Setup nothing() {
            return new Setup();
        }

        Setup password(String key, Route route) {
            Setup setup = copy();
            setup.password = key;
            setup.passwordRoute = route;
            return setup;
        }

        Setup next(String key, Route route) {
            Setup setup = copy();
            setup.next = key;
            setup.nextRoute = route;
            return setup;
        }

        Setup previous(String key, Route route) {
            Setup setup = copy();
            setup.previous = singletonList(key);
            setup.previousRoute = route;
            return setup;
        }

        Setup legacy(String key, Route route) {
            Setup setup = copy();
            setup.legacy = key;
            setup.legacyRoute = route;
            return setup;
        }

        private Setup copy() {
            Setup setup = new Setup();
            setup.password = password;
            setup.passwordRoute = passwordRoute;
            setup.next = next;
            setup.nextRoute = nextRoute;
            setup.previous = previous;
            setup.previousRoute = previousRoute;
            setup.legacy = legacy;
            setup.legacyRoute = legacyRoute;
            return setup;
        }

        /**
         * A next key and read-only keys need a named legacy password, and closing its reader needs a key that
         * seals.
         */
        boolean isRefused() {
            boolean opensWithoutSealing = next != null || !previous.isEmpty();
            return (opensWithoutSealing && legacy == null) || (NONE.equals(legacy) && password == null);
        }

        /**
         * The legacy password when named. Otherwise the password read from the configuration, which wrote the
         * unmarked values before this version, and the shipped password when none was configured.
         */
        String legacyKey() {
            if (legacy != null) {
                return legacy;
            }
            return passwordRoute == Route.CONFIGURATION ? password : SHIPPED;
        }

        boolean holds(String key) {
            return key.equals(password) || key.equals(next) || previous.contains(key);
        }

        @Override
        public String toString() {
            return "[password=" + describe(password, passwordRoute) + ", next=" + describe(next, nextRoute)
                    + ", previous=" + describe(previous.isEmpty() ? null : previous.get(0), previousRoute)
                    + ", legacy=" + describe(legacy, legacyRoute) + "]";
        }

        private static String describe(String key, Route route) {
            return key == null ? "-" : name(key) + " (" + route.name().toLowerCase() + ")";
        }
    }
}
