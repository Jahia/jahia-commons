/**
 * This file is part of Jahia, next-generation open source CMS:
 * Jahia's next-generation, open source CMS stems from a widely acknowledged vision
 * of enterprise application convergence - web, search, document, social and portal -
 * unified by the simplicity of web content management.
 *
 * For more information, please visit http://www.jahia.com.
 *
 * Copyright (C) 2002-2014 Jahia Solutions Group SA. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * As a special exception to the terms and conditions of version 2.0 of
 * the GPL (or any later version), you may redistribute this Program in connection
 * with Free/Libre and Open Source Software ("FLOSS") applications as described
 * in Jahia's FLOSS exception. You should have received a copy of the text
 * describing the FLOSS exception, and it is also available here:
 * http://www.jahia.com/license
 *
 * Commercial and Supported Versions of the program (dual licensing):
 * alternatively, commercial and supported versions of the program may be used
 * in accordance with the terms and conditions contained in a separate
 * written agreement between you and Jahia Solutions Group SA.
 *
 * If you are unsure which license is appropriate for your use,
 * please contact the sales department at sales@jahia.com.
 */
package org.jahia.commons;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.List;

/**
 * Utility class for parsing and executing SQL scripts.
 * 
 * @author Sergiy Shyrkov
 */
public final class DatabaseScripts {

    /**
     * Initializes an instance of this class.
     */
    private DatabaseScripts() {
        super();
    }

    /**
     * Parses the provider content into a list of executable SQL statements also considering multi-line statements.
     * 
     * @param reader
     *            the content of the SQL script to be parsed
     * @return the list of SQL statements to execute
     * @throws IOException
     *             in case of reading error
     */
    public static List<String> getScriptStatements(Reader reader) throws IOException {
        List<String> scriptsRuntimeList = new LinkedList<String>();

        BufferedReader buffered = new BufferedReader(reader);
        try {
            String buffer = "";

            StringBuilder curSQLStatement = new StringBuilder();
            while ((buffer = buffered.readLine()) != null) {
                if (buffer != null && buffer.trim().equals("/")) {
                    // '/' indicates the end of the PL/SQL script for Oracle -> skip it here
                    continue;
                }

                // let's check for comments.
                int commentPos = buffer.indexOf('#');
                if ((commentPos != -1) && (!isInQuotes(buffer, commentPos))) {
                    buffer = buffer.substring(0, commentPos);
                }
                commentPos = buffer.indexOf("//");
                if ((commentPos != -1) && (!isInQuotes(buffer, commentPos))) {
                    buffer = buffer.substring(0, commentPos);
                }
                commentPos = buffer.indexOf("/*");
                if ((commentPos != -1) && (!isInQuotes(buffer, commentPos))) {
                    buffer = buffer.substring(0, commentPos);
                }
                commentPos = buffer.indexOf("REM ");
                if ((commentPos != -1) && (!isInQuotes(buffer, commentPos))) {
                    buffer = buffer.substring(0, commentPos);
                }
                commentPos = buffer.indexOf("--");
                if ((commentPos != -1) && (!isInQuotes(buffer, commentPos))) {
                    buffer = buffer.substring(0, commentPos);
                }

                // is the line after comment removal ?
                if (buffer.trim().length() == 0) {
                    continue;
                }

                buffer = buffer.trim();

                if (buffer.endsWith(";")) {
                    // found seperator char in the script file, finish constructing
                    curSQLStatement.append(buffer.substring(0,
                            buffer.endsWith("end;") ? buffer.length() : buffer.length() - 1));
                    String sqlStatement = curSQLStatement.toString().trim();
                    if (!"".equals(sqlStatement)) {
                        scriptsRuntimeList.add(sqlStatement);
                    }
                    curSQLStatement = new StringBuilder();
                } else {
                    curSQLStatement.append(buffer);
                    curSQLStatement.append('\n');
                }

            }
            String sqlStatement = curSQLStatement.toString().trim();
            if (!"".equals(sqlStatement)) {
                scriptsRuntimeList.add(sqlStatement);
            }

        } finally {
            buffered.close();
        }

        return scriptsRuntimeList;
    }

    private static boolean isInQuotes(String sqlStatement, int pos) {
        if (pos < 0) {
            return false;
        }
        String beforeStr = sqlStatement.substring(0, pos);
        int quoteCount = 0;
        int curPos = 0;
        int quotePos = beforeStr.indexOf('\'');
        while (quotePos != -1) {
            quoteCount++;
            curPos = quotePos + 1;
            quotePos = beforeStr.indexOf('\'', curPos);
        }
        if (quoteCount % 2 == 0) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Executes the content of the provided SQL script file.
     * 
     * @param scriptContent
     *            the SQL script file content
     * @param conn
     *            the DB connection to execute SQL statements
     * @throws SQLException
     *             in case of DB errors
     * @throws IOException
     *             in case of a script reading errors
     */
    public static void executeScript(Reader scriptContent, Connection conn) throws SQLException, IOException {
        executeStatements(getScriptStatements(scriptContent), conn);
    }

    /**
     * Executes the the provided SQL statements.
     * 
     * @param scriptContent
     *            the SQL script file content
     * @param conn
     *            the DB connection to execute SQL statements
     * @throws SQLException
     *             in case of DB errors
     */
    public static void executeStatements(List<String> sqlStatements, Connection conn) throws SQLException {
        if (sqlStatements.isEmpty()) {
            return;
        }

        Statement stmt = conn.createStatement();
        try {
            for (String sql : sqlStatements) {
                try {
                    stmt.execute(sql);
                } catch (SQLException e) {
                    final String lowerCaseSql = sql.toLowerCase();
                    if (lowerCaseSql.startsWith("drop ") || lowerCaseSql.contains(" drop ")
                            || lowerCaseSql.contains("\ndrop ") || lowerCaseSql.contains(" drop\n")
                            || lowerCaseSql.contains("\ndrop\n")) {
                        // ignore
                    } else if (lowerCaseSql.startsWith("alter table") || lowerCaseSql.startsWith("create index")) {
                        System.err.println("Error executing statement:\n" + sql);
                        System.err.println(e.getMessage());
                        e.printStackTrace();
                    } else {
                        throw e;
                    }
                }
            }
        } finally {
            if (!stmt.isClosed()) {
                stmt.close();
            }
        }
    }
}
