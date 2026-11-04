---
jahia-commons: patch
---

`DatabaseScripts.executeStatements` now logs a failed `ALTER TABLE` or `CREATE INDEX` statement as a warning through `java.util.logging`, instead of printing it to the standard error stream. The script still goes on after such a statement.
