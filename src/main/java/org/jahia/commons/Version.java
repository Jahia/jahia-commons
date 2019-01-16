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
package org.jahia.commons;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class represents a product version, and can be initialized by a String.
 * This is a utility object to compare versions easily.
 * <p/>
 * Currently it recognized Strings of the form :
 * <p/>
 * major.minor.servicepack.hotfix.other1.other2.*Bbetanumber
 * major.minor.servicepack.hotfix.other1.other2.*RCbetanumber
 * major.minor.servicepack.hotfix.other1.other2.*_updatenumber
 * major.minor.servicepack.hotfix.other1.other2.*_updatenumber-bbuildernumber
 * major.minor.servicepack.hotfix.other1.other2.*_updatenumber-qualifier1-qualifier2
 * <p/>
 * "B" and "RC" can be uppercase or minor case, the comparison is case insensitive
 * for the moment.
 * <p/>
 * <p>Copyright: Copyright (c) 2002</p>
 * <p>Company: Jahia Inc.</p>
 *
 * @author Serge Huber
 * @version 3.0
 */

public class Version implements Comparable<Version> {

    private static final Pattern VERSION_NUMBER_PATTERN = Pattern.compile("^([0-9\\.]*[0-9]+)(.*)");

    public static final String MAVEN_LATEST_VERSION = "LATEST";
    public static final String MAVEN_SNAPSHOT_VERSION = "SNAPSHOT";
    public static final Pattern MAVEN_VERSION_FILE_PATTERN = Pattern.compile("^(.*)-([0-9]{8}.[0-9]{6})-([0-9]+)$");

    public static final Pattern FILE_NAME_VERSION_PATTERN = Pattern.compile("^(.*?)-(([0-9\\.]*[0-9]+)(.*))?$");

    private List<Integer> orderedVersionNumbers = new ArrayList<Integer>();
    private int betaNumber = -1;
    private int releaseCandidateNumber = -1;
    private String version;
    private String versionPartSuffix;
    private String updateMarker;
    private List<String> qualifiers = new ArrayList<String>();

    /**
     * Constructor. See class definition for syntax of the version string
     *
     * @param versionString the String containing the version to analyze. See
     *                      class description for more details.
     * @throws NumberFormatException if there was a problem parsing the string
     *                               containing the version.
     */
    public Version(final String versionString) throws NumberFormatException {
        if (versionString == null) {
            throw new NumberFormatException("Null string passed as version !");
        }
        if (versionString.length() == 0) {
            throw new NumberFormatException("Empty string passed as version !");
        }
        String trimmedVersionString = versionString.trim();
        String versionPart = null;
        String numberedVersionPart = null;
        StringTokenizer tokenizer = new StringTokenizer(trimmedVersionString, "-");
        versionPart = tokenizer.nextToken();
        while (tokenizer.hasMoreTokens()) {
            qualifiers.add(tokenizer.nextToken());
        }
        Matcher versionPartMatcher = VERSION_NUMBER_PATTERN.matcher(versionPart);
        if (!versionPartMatcher.matches()) {
            qualifiers.add(0, versionPart);
            versionPart = null;
        } else {
            numberedVersionPart = versionPartMatcher.group(1);
            versionPartSuffix = versionPartMatcher.group(2);
        }

        if (versionPart != null) {
            versionPart = versionPart.toLowerCase();
            int betaPos = versionPart.indexOf("b");
            int rcPos = versionPart.indexOf("rc");

            if (betaPos != -1) {
                String betaString = versionPart.substring(betaPos + 1).trim();
                String rest = versionPart.substring(0, betaPos);
                try {
                    betaNumber = Integer.parseInt(betaString);
                    versionPart = rest;
                    versionPartSuffix = null;
                } catch (NumberFormatException e) {
                    // does not seem like a beta number: we will consider this part as suffix
                }
            } else if (rcPos != -1) {
                String rcString = versionPart.substring(rcPos + 2).trim();
                String rest = versionPart.substring(0, rcPos);
                try {
                    releaseCandidateNumber = Integer.parseInt(rcString);
                    versionPart = rest;
                    versionPartSuffix = null;
                } catch (NumberFormatException e) {
                    // does not seem like an RC number: we will consider this part as suffix
                }
            }

            int underscorePos = versionPart.indexOf("_");
            if (underscorePos != -1) {
                updateMarker = versionPart.substring(underscorePos + 1).trim();
                versionPart = versionPart.substring(0, underscorePos).trim();
                versionPartSuffix = null;
            }

            StringTokenizer versionTokenizer = new StringTokenizer(numberedVersionPart, ".");
            while (versionTokenizer.hasMoreTokens()) {
                String curToken = versionTokenizer.nextToken().trim();
                try {
                    int curVersionNumber = Integer.parseInt(curToken);
                    orderedVersionNumbers.add(new Integer(curVersionNumber));
                } catch (NumberFormatException nfe) {
                    // we're out of numbers, this is not a string anymore. Normally this is not possible since we used
                    // a regexp to match only numbers
                }
            }
        }
    }

    String getBaseVersionString() {
        StringBuffer baseVersionBuf = new StringBuffer();
        for (Integer orderedVersionNumber : orderedVersionNumbers) {
            baseVersionBuf.append(orderedVersionNumber);
            baseVersionBuf.append(".");
        }
        String baseVersionString = baseVersionBuf.toString();
        return baseVersionString.substring(0, baseVersionString.length() -1);
    }

    /**
     * Returns true if the version represents a beta version
     *
     * @return true if a beta version.
     */
    public boolean isBeta() {
        if (betaNumber != -1) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns true if the version represents a release candidate version.
     *
     * @return true is release candidate
     */
    public boolean isReleaseCandidate() {
        if (releaseCandidateNumber != -1) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns true if the version represents final (that is to say non-beta
     * and non-release candidate) version.
     *
     * @return true if version is neither a beta or a release candidate version.
     */
    public boolean isFinal() {
        if ((betaNumber == -1) &&
                (releaseCandidateNumber == -1)) {
            return true;
        } else {
            return false;
        }
    }

    public String getVersionPartSuffix() {
        return versionPartSuffix;
    }

    /**
     * Generates a String from the internal data structure. This is not
     * necessarily equals to the String passed to the constructor, especially
     * since here we return a lower case string.
     *
     * @return a lower case String representing the version
     */
    @Override
    public String toString() {
        if (version == null) {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < orderedVersionNumbers.size(); i++) {
                Integer curVersionNumber = (Integer) orderedVersionNumbers.get(i);
                result.append(curVersionNumber.intValue());
                if (i < (orderedVersionNumbers.size() - 1)) {
                    result.append(".");
                }
            }
            if (versionPartSuffix != null) {
                result.append(versionPartSuffix);
            }
            if (betaNumber != -1) {
                result.append("b");
                result.append(betaNumber);
            } else if (releaseCandidateNumber != -1) {
                result.append("rc");
                result.append(releaseCandidateNumber);
            }
            if (updateMarker != null) {
                result.append("_");
                result.append(updateMarker);
            }
            if (qualifiers.size() > 0) {
                for (String qualifier : qualifiers) {
                    result.append("-");
                    result.append(qualifier);
                }
            }
            version = result.toString();
        }
        return version;
    }

    /**
     * Implements the compareTo method from the Comparable interface. This
     * allows this class to be sorted by version number.
     * <p/>
     * ComparisonImpl is done the following way :
     * 1. compares the version number until there is no more to compare
     * 2. compares the "state" (beta, release candidate, final)
     * <p/>
     * Examples :
     * 4.0, 4.0.1 returns -1
     * 4.0B1, 4.0.1B1 returns -1
     * 4.1.0, 4.0.1 returns 1
     * 4.0.0, 4.0.0 return 0
     * 4.0.1B1, 4.0.1RC2 returns -1
     * ...
     *
     * @param o a Version object to compare to. If this is not a Version class
     *          object, then a ClassCastException will be raised
     * @return -1 if this version is "smaller" than the one specified. 0 if
     *         it is equal, or 1 if it bigger.
     * @throws ClassCastException if the passed parameter (o) is not a Version
     *                            class object.
     */
    @Override
    public int compareTo(Version o) {
        Version rightVersion = (Version) o;
        List<Integer> rightOrderedVersionNumbers = rightVersion.getOrderedVersionNumbers();

        if (this.equals(rightVersion)) {
            return 0;
        }

        if (orderedVersionNumbers.size() == rightOrderedVersionNumbers.size()) {
            for (int i = 0; i < orderedVersionNumbers.size(); i++) {
                Integer versionNumber = orderedVersionNumbers.get(i);
                Integer rightVersionNumber = rightOrderedVersionNumbers.get(i);
                if (versionNumber.intValue() != rightVersionNumber.intValue()) {
                    return versionNumber.compareTo(rightVersionNumber);
                }
            }
            // now we must compare beta numbers, release candidate number and regular versions
            // to determine which is higher.
            if (isBeta() && rightVersion.isBeta()) {
                if (betaNumber < rightVersion.getBetaNumber()) {
                    return -1;
                } else {
                    return 1;
                }
            }

            if (isReleaseCandidate() && rightVersion.isReleaseCandidate()) {
                if (releaseCandidateNumber < rightVersion.getReleaseCandidateNumber()) {
                    return -1;
                } else {
                    return 1;
                }
            }

            if (isBeta() && rightVersion.isReleaseCandidate()) {
                return -1;
            }
            if (isBeta() && rightVersion.isFinal()) {
                return -1;
            }
            if (isReleaseCandidate() && rightVersion.isBeta()) {
                return 1;
            }
            if (isReleaseCandidate() && rightVersion.isFinal()) {
                return -1;
            }
            if (isFinal() && rightVersion.isBeta()) {
                return 1;
            }
            if (isFinal() && rightVersion.isReleaseCandidate()) {
                return 1;
            }

            return 0;

        } else if (orderedVersionNumbers.size() < rightOrderedVersionNumbers.size()) {
            // this version has less numbers that the right one.
            for (int i = 0; i < orderedVersionNumbers.size(); i++) {
                Integer versionNumber = (Integer) orderedVersionNumbers.get(i);
                Integer rightVersionNumber = (Integer) rightOrderedVersionNumbers.get(i);
                if (versionNumber.intValue() != rightVersionNumber.intValue()) {
                    return versionNumber.compareTo(rightVersionNumber);
                }
            }
            return -1;
        } else {
            // the right version has less number than this one.
            for (int i = 0; i < rightOrderedVersionNumbers.size(); i++) {
                Integer versionNumber = (Integer) orderedVersionNumbers.get(i);
                Integer rightVersionNumber = (Integer) rightOrderedVersionNumbers.get(i);
                if (versionNumber.intValue() != rightVersionNumber.intValue()) {
                    return versionNumber.compareTo(rightVersionNumber);
                }
            }
            return 1;
        }
    }

    /**
     * Returns an array list of Integer objects containing the version number.
     * index 0 is the major version number, index 1 is the minor, etc... This
     * method does not return beta or release candidate versions.
     *
     * @return an List containing Integers that represent the version
     *         number. The ordered of these are significant
     */
    public List<Integer> getOrderedVersionNumbers() {
        return orderedVersionNumbers;
    }

    /**
     * Returns the beta number part of the version number
     *
     * @return an integer representing the beta number, or -1 if this is not
     *         a beta version.
     */
    public int getBetaNumber() {
        return betaNumber;
    }

    /**
     * Returns the release candidate number part of the version number
     *
     * @return an integer representing the release candidate  number, or -1
     *         if this is not a release candidate version.
     */
    public int getReleaseCandidateNumber() {
        return releaseCandidateNumber;
    }

    /**
     * Returns the update marker string, located after the underscore. This is usually a numeric value but we support
     * String values
     *
     * @return
     */
    public String getUpdateMarker() {
        return updateMarker;
    }

    /**
     * Return the list of qualifiers if there were any specified.
     *
     * @return
     */
    public List<String> getQualifiers() {
        return qualifiers;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;

        if (obj != null && this.getClass() == obj.getClass()) {
            Version rightVersion = (Version) obj;
            // first we create copies of the version number lists to be able to normalize them if necessary.
            List<Integer> normalizedOrderedVersionNumbers = new ArrayList<Integer>(orderedVersionNumbers);
            List<Integer> normalizedRightOrderedVersionNumbers = new ArrayList<Integer>(rightVersion.getOrderedVersionNumbers());
            // version numbers might not have same length, we must first normalize the length to compare them since
            // 1.5 is equal to 1.5.0.0
            if (normalizedOrderedVersionNumbers.size() < normalizedRightOrderedVersionNumbers.size()) {
                int sizeDiff = normalizedRightOrderedVersionNumbers.size() - normalizedOrderedVersionNumbers.size();
                for (int i = 0; i < sizeDiff; i++) {
                    normalizedOrderedVersionNumbers.add(0);
                }
            } else if (normalizedOrderedVersionNumbers.size() > normalizedRightOrderedVersionNumbers.size()) {
                int sizeDiff = normalizedOrderedVersionNumbers.size() - normalizedRightOrderedVersionNumbers.size();
                for (int i = 0; i < sizeDiff; i++) {
                    normalizedRightOrderedVersionNumbers.add(0);
                }
            }
            if (betaNumber != rightVersion.getBetaNumber()) {
                return false;
            }
            if (releaseCandidateNumber != rightVersion.getReleaseCandidateNumber()) {
                return false;
            }
            for (int i = 0; i < normalizedOrderedVersionNumbers.size(); i++) {
                Integer leftVersionNumber = normalizedOrderedVersionNumbers.get(i);
                Integer rightVersionNumber = normalizedRightOrderedVersionNumbers.get(i);
                if (leftVersionNumber.intValue() != rightVersionNumber.intValue()) {
                    return false;
                }
            }
            if ((updateMarker != null) && (rightVersion.getUpdateMarker() != null)) {
                if (!updateMarker.equals(rightVersion.getUpdateMarker())) {
                    return false;
                }
            } else {
                if ((updateMarker == null) && (rightVersion.getUpdateMarker() == null)) {
                } else {
                    return false;
                }
            }
            if (!qualifiers.equals(rightVersion.getQualifiers())) {
                return false;
            }
            // if we got here it means the version are equal.
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns the major version number, which is the first number in a X.X.X.X format or 0 if there is no first number
     *
     * @return
     */
    public int getMajorVersion() {
        if (orderedVersionNumbers.size() > 0) {
            return orderedVersionNumbers.get(0);
        } else {
            return 0;
        }
    }

    /**
     * Returns the minor version number, which is the second number in a X.X.X.X format or 0 if there is no second number
     *
     * @return
     */
    public int getMinorVersion() {
        if (orderedVersionNumbers.size() > 1) {
            return orderedVersionNumbers.get(1);
        } else {
            return 0;
        }
    }

    /**
     * Returns the service pack version number, which is the third number in a X.X.X.X format or 0 if there is no third number
     *
     * @return
     */
    public int getServicePackVersion() {
        if (orderedVersionNumbers.size() > 2) {
            return orderedVersionNumbers.get(2);
        } else {
            return 0;
        }
    }

    /**
     * Returns the patch version number, which is the fourth number in a X.X.X.X format or 0 if there is no fourth number
     *
     * @return
     */
    public int getPatchVersion() {
        if (orderedVersionNumbers.size() > 3) {
            return orderedVersionNumbers.get(3);
        } else {
            return 0;
        }
    }

    public static Version fromMavenFileName(String fileNameWithoutExtension) {
        Matcher fileNameMatcher = FILE_NAME_VERSION_PATTERN.matcher(fileNameWithoutExtension);
        if (fileNameMatcher.matches()) {
            return new Version(fileNameMatcher.group(2));
        }
        return null;
    }
}