package org.jahia.commons.encryption;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

/**
 * Covers how a numbered family of keys is read from the environment and the system properties.
 */
public class ConfigurationUtilsTest {

    private static final String ENV = "PREVIOUS_";
    private static final String PROP = "previous.";

    @Test
    public void numbersAreOrderedByTheirValue() {
        assertEquals(asList("two", "ten"), values(emptyMap(), properties("10", "ten", "2", "two")));
    }

    @Test
    public void twoSpellingsOfOneNumberAreOneNumber() {
        assertEquals(asList("from the environment"),
                values(singletonMap(ENV + "1", "from the environment"), properties("01", "from a property")));
    }

    @Test
    public void theEnvironmentVariableWinsForTheSameNumber() {
        assertEquals(asList("from the environment", "only a property"),
                values(singletonMap(ENV + "1", "from the environment"),
                        properties("1", "from a property", "2", "only a property")));
    }

    @Test(expected = IllegalArgumentException.class)
    public void twoSpellingsOfOneNumberInOneRouteAreRefused() {
        values(emptyMap(), properties("1", "one", "01", "another one"));
    }

    @Test
    public void aSuffixOutsideTheAsciiDigitsIsNotANumber() {
        assertEquals(asList("one"), values(emptyMap(), properties("1", "one", "\u0662", "two", "1a", "x")));
    }

    private static List<String> values(Map<String, String> environment, Properties properties) {
        return ConfigurationUtils.getConfigValues(ENV, PROP, environment, properties);
    }

    private static Properties properties(String... suffixesAndValues) {
        Properties properties = new Properties();
        for (int i = 0; i < suffixesAndValues.length; i += 2) {
            properties.setProperty(PROP + suffixesAndValues[i], suffixesAndValues[i + 1]);
        }
        return properties;
    }
}
