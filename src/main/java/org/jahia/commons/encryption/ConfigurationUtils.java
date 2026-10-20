/*
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2019 Jahia Solutions Group SA. All rights reserved.
 *
 *     THIS FILE IS AVAILABLE UNDER TWO DIFFERENT LICENSES:
 *     1/GPL OR 2/JSEL
 *
 *     1/ GPL
 *     ==================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE GPL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *     2/ JSEL - Commercial and Supported Versions of the program
 *     ===================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE JSEL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     Alternatively, commercial and supported versions of the program - also known as
 *     Enterprise Distributions - must be used in accordance with the terms and conditions
 *     contained in a separate written agreement between you and Jahia Solutions Group SA.
 *
 *     If you are unsure which license is appropriate for your use,
 *     please contact the sales department at sales@jahia.com.
 */
package org.jahia.commons.encryption;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Configuration utilities for retrieving values from environment variables and system properties.
 *
 * @author Jahia Solutions Group SA
 */
public final class ConfigurationUtils {

    /** Orders numeric suffixes by their value, and two spellings of one value by their text. */
    private static final Comparator<String> BY_NUMBER =
            Comparator.comparing((String suffix) -> new BigInteger(suffix)).thenComparing(Comparator.naturalOrder());

    /**
     * Gets configuration value from environment variable, system property, or default value.
     * Environment variables take precedence over system properties.
     *
     * @param envKey the environment variable key
     * @param propKey the system property key
     * @param defaultValue the default value if neither env var nor system property is set
     * @return the configuration value
     */
    public static String getConfigValue(String envKey, String propKey, String defaultValue) {
        // Check environment variable first
        String value = System.getenv(envKey);
        if (value != null && !value.trim().isEmpty()) {
            return value;
        }

        // Check system property second
        value = System.getProperty(propKey);
        if (value != null && !value.trim().isEmpty()) {
            return value;
        }

        // Return default value
        return defaultValue;
    }

    /**
     * Gets the values of a numbered family of keys, such as {@code PREFIX_1} and {@code prefix.1}, ordered by
     * their number. A number is written in ASCII digits, and a number may be skipped, so removing one key
     * leaves the others in place. When an environment variable and a system property carry the same
     * suffix, the environment variable takes precedence, as {@link #getConfigValue} does for a single key.
     * A blank value counts as unset.
     *
     * @param envPrefix the environment variable prefix, which the number follows
     * @param propPrefix the system property prefix, which the number follows
     * @return the values in ascending order of their number, empty when none is set
     */
    public static List<String> getConfigValues(String envPrefix, String propPrefix) {
        Map<String, String> bySuffix = new TreeMap<>(BY_NUMBER);
        Properties properties = System.getProperties();
        for (String name : properties.stringPropertyNames()) {
            putIfNumbered(bySuffix, propPrefix, name, properties.getProperty(name));
        }
        for (Map.Entry<String, String> variable : System.getenv().entrySet()) {
            putIfNumbered(bySuffix, envPrefix, variable.getKey(), variable.getValue());
        }
        return new ArrayList<>(bySuffix.values());
    }

    private static void putIfNumbered(Map<String, String> bySuffix, String prefix, String key, String value) {
        if (!key.startsWith(prefix) || value == null || value.trim().isEmpty()) {
            return;
        }
        String suffix = key.substring(prefix.length());
        if (!suffix.isEmpty() && suffix.chars().allMatch(c -> c >= '0' && c <= '9')) {
            bySuffix.put(suffix, value);
        }
    }

    /**
     * Initializes an instance of this class.
     */
    private ConfigurationUtils() {
        super();
    }
}
