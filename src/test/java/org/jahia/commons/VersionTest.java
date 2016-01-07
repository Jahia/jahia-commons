/**
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2016 Jahia Solutions Group SA. All rights reserved.
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
package org.jahia.commons;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Unit test for version parsing class.
 */
public class VersionTest {

    @Test
    public void testVersionParsing() {
        Version version = new Version("1.0");
        Assert.assertEquals("Major version should be 1", 1, version.getMajorVersion());
        Assert.assertEquals("Minor version should be 0", 0, version.getMinorVersion());
        Assert.assertEquals("Service pack version should be 0", 0, version.getServicePackVersion());
        Assert.assertEquals("Patch version should be 0", 0, version.getPatchVersion());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        Assert.assertEquals("Version " + version + " toString not equal", "1.0", version.toString());
        boolean exception = false;
        try {
            version = new Version(null);
        } catch (NumberFormatException nfe) {
            exception = true;
        }
        Assert.assertTrue("Version " + version + " is invalid but not detected as such", exception);
        version = new Version("1.1.1.1.1.1.1.1");
        Assert.assertEquals("Version " + version + " toString not equal", "1.1.1.1.1.1.1.1", version.toString());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        version = new Version("1.1.rc1");
        Assert.assertTrue("Version " + version + " should be identified as release candidate", version.isReleaseCandidate());
        version = new Version("1.1b1");
        Assert.assertTrue("Version " + version + " should be identified as beta", version.isBeta());
        version = new Version("6.5-SNAPSHOT");
        Assert.assertEquals("Version " + version + " toString not equal", "6.5-SNAPSHOT", version.toString());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        version = new Version("6.5b1-B1");
        Assert.assertEquals("Version " + version + " toString not equal", "6.5b1-B1", version.toString());
        Assert.assertTrue("Version " + version + " should be identified as beta", version.isBeta());
        List<String> qualifiers = new ArrayList<String>();
        qualifiers.add("b07");
        qualifiers.add("334");
        qualifiers.add("10M3326");
        version = new Version("1.6.0_24-b07-334-10M3326");
        Assert.assertEquals("Version " + version + " toString not equal", "1.6.0_24-b07-334-10M3326", version.toString());
        Assert.assertEquals("Major version should be 1", 1, version.getMajorVersion());
        Assert.assertEquals("Minor version should be 6", 6, version.getOrderedVersionNumbers().get(1).intValue());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        Assert.assertEquals("Version " + version + " qualifiers are invalid", version.getQualifiers(), qualifiers);
        version = new Version("  1.6.0_24-b07-334-10M3326   ");
        Assert.assertEquals("Version " + version + " toString not equal", "1.6.0_24-b07-334-10M3326", version.toString());
        Assert.assertEquals("Major version should be 1", 1, version.getMajorVersion());
        Assert.assertEquals("Minor version should be 6", 6, version.getOrderedVersionNumbers().get(1).intValue());
        Assert.assertEquals("Update version should be 24", "24", version.getUpdateMarker());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        Assert.assertEquals("Version " + version + " qualifiers are invalid", version.getQualifiers(), qualifiers);
        version = new Version(" 1.6.0_u24-b07-334-10M3326");
        Assert.assertEquals("Version " + version + " toString not equal", "1.6.0_u24-b07-334-10M3326", version.toString());
        Assert.assertEquals("Major version should be 1", 1, version.getMajorVersion());
        Assert.assertEquals("Minor version should be 6", 6, version.getOrderedVersionNumbers().get(1).intValue());
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        Assert.assertEquals("Version " + version + " qualifiers are invalid", version.getQualifiers(), qualifiers);
        version = new Version("r06");
        qualifiers.clear();
        qualifiers.add("r06");
        Assert.assertEquals("Version " + version + " should be only with classifier r06", qualifiers, version.getQualifiers());
        version = new Version("1.6.0u24-b07-334-10M3326");
        Assert.assertEquals("Version " + version + " toString does not match 1.6.0u24-b07-334-10M3326 ", "1.6.0u24-b07-334-10M3326", version.toString());
        version = new Version("6.5-BETA2");
        Assert.assertTrue("Version " + version + " should be identified as final", version.isFinal());
        qualifiers.clear();
        qualifiers.add("BETA2");
        Assert.assertEquals("Version " + version + " qualifier should be BETA2", version.getQualifiers(), qualifiers);

        qualifiers.clear();
        version = new Version("3.4.0.GA.");
        Assert.assertEquals("Version " + version + " part suffix should be .GA.", ".GA.", version.getVersionPartSuffix());
        Assert.assertEquals("Version " + version + " base version should be 3.4.0", "3.4.0", version.getBaseVersionString());
        Assert.assertTrue("Version " + version + " qualifiers should be empty", version.getQualifiers().size() == 0);

        // OSGi versions with qualifiers;
        qualifiers.clear();
        version = new Version("2.0.0.SNAPSHOT");
        Assert.assertEquals("Version " + version + " part suffix should be .SNAPSHOT", ".SNAPSHOT", version.getVersionPartSuffix());
        Assert.assertEquals("Version " + version + " base version should be 2.0.0", "2.0.0", version.getBaseVersionString());
        Assert.assertTrue("Version " + version + " qualifiers should be empty", version.getQualifiers().size() == 0);

        try {
            version = new Version("");
            Assert.assertTrue("Empty version number should generate a NumberFormatException", true);
        } catch (NumberFormatException nfe) {
            // this is the expected case
        }

    }

    @Test
    public void testVersionComparison() {
        Version lowerVersion = new Version("1.5");
        Version higherVersion = new Version("1.7");

        Version testVersion = new Version("1.6.0_24-b07-334-10M3326");
        Assert.assertEquals("Test version should be higher than lower version", -1, lowerVersion.compareTo(testVersion));
        Assert.assertEquals("Test version should be lower than higher version", 1, higherVersion.compareTo(testVersion));

        testVersion = new Version("1.6-SNAPSHOT");
        Assert.assertEquals("Test version should be higher than lower version", -1, lowerVersion.compareTo(testVersion));
        Assert.assertEquals("Test version should be lower than higher version", 1, higherVersion.compareTo(testVersion));

        testVersion = new Version("1.5-SNAPSHOT");
        Assert.assertEquals("Test version should be equal to lower version", 0, lowerVersion.compareTo(testVersion));
        Assert.assertEquals("Test version should be lower than higher version", 1, higherVersion.compareTo(testVersion));

        testVersion = new Version("1.5.0.0");
        Assert.assertEquals("Test version should be equal to lower version", true, lowerVersion.equals(testVersion));
        Assert.assertEquals("Lower version should be equal to test version", true, testVersion.equals(lowerVersion));
        Assert.assertEquals("Test version should be equal to lower version", 0, lowerVersion.compareTo(testVersion));
        Assert.assertEquals("Lower version should be equal to test version", 0, testVersion.compareTo(lowerVersion));

    }

    @Test
    public void testFileNameParsing() {
        Version version = Version.fromMavenFileName("geronimo-j2ee-connector_1.5_spec-2.0.0");
        Assert.assertEquals("Version " + version + " does not match", new Version("2.0.0"), version);
        version = Version.fromMavenFileName("abdera-i18n-0.4.0-incubating");
        Assert.assertEquals("Version " + version + " does not match", new Version("0.4.0-incubating"), version);
        Assert.assertEquals("Version " + version + " base version does not match", "0.4.0", version.getBaseVersionString());
        version = Version.fromMavenFileName("deployers-4.0-20130129.191029-6");
        Assert.assertEquals("Version " + version + " does not match", new Version("4.0-20130129.191029-6"), version);
        version = Version.fromMavenFileName("eclipse-core-runtime-20070801");
        Assert.assertEquals("Version " + version + " does not match", new Version("20070801"), version);
        version = Version.fromMavenFileName("geronimo-stax-api_1.0_spec-1.0.1");
        Assert.assertEquals("Version " + version + " does not match", new Version("1.0.1"), version);
        version = Version.fromMavenFileName("jackrabbit-api-2.4.2-rev1346887-patch9");
        Assert.assertEquals("Version " + version + " does not match", new Version("2.4.2-rev1346887-patch9"), version);
        version = Version.fromMavenFileName("jahia-api-6.7.0.0-SNAPSHOT");
        Assert.assertEquals("Version " + version + " does not match", new Version("6.7.0.0-SNAPSHOT"), version);
        version = Version.fromMavenFileName("jodconverter-core-3.0-beta-4-jahia3");
        Assert.assertEquals("Version " + version + " does not match", new Version("3.0-beta-4-jahia3"), version);
        version = Version.fromMavenFileName("js-1.7R2");
        Assert.assertEquals("Version " + version + " does not match", new Version("1.7R2"), version);
        version = Version.fromMavenFileName("guava-r06");
        Assert.assertTrue("Version " + version + " is not parseable by this implementation", version == null);
        version = Version.fromMavenFileName("jakarta-slide-webdavlib-2.2pre1-SLIDE-386476");
        Assert.assertEquals("Version " + version + " does not match", new Version("2.2pre1-SLIDE-386476"), version);
        version = Version.fromMavenFileName("geocoder-java-0.9-jdk5");
        Assert.assertEquals("Version " + version + " does not match", new Version("0.9-jdk5"), version);

        // Eclise version numbers do not work correctly yet
        /*
        version = Version.fromMavenFileName("org.eclipse.equinox.p2.publisher_1.1.2.v20100824-2220");
        Assert.assertEquals("Version " + version + " does not match", new Version("1.1.2.v20100824-2220"), version);
        version = Version.fromMavenFileName("overlay.com.android.ide.eclipse.adt.overlay_20.0.0.v201206242043-391819");
        Assert.assertEquals("Version " + version + " does not match", new Version("20.0.0.v201206242043-391819"), version);
        version = Version.fromMavenFileName("org.eclipse.update.configurator.manipulator_3.1.0.v201008301800_r35");
        Assert.assertEquals("Version " + version + " does not match", new Version("3.1.0.v201008301800_r35"), version);
        version = Version.fromMavenFileName("org.eclipse.equinox.frameworkadmin.equinox.source_1.0.101.R35x_v20091214");
        Assert.assertEquals("Version " + version + " does not match", new Version("1.0.101.R35x_v20091214"), version);
        */
    }
}
