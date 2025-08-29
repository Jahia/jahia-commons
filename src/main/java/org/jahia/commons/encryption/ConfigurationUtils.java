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

/**
 * Configuration utilities for retrieving values from environment variables and system properties.
 *
 * @author Jahia Solutions Group SA
 */
public final class ConfigurationUtils {

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
     * Initializes an instance of this class.
     */
    private ConfigurationUtils() {
        super();
    }
}
