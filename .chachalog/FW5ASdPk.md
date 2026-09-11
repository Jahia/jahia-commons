---
jahia-commons: minor
---

Changed the stored form of encrypted values so that each value records its format, and used AES-GCM for new values.

A value written by this version cannot be read by an earlier version, so take that into account before you downgrade.

An installation that sets an encryption password of its own names the key that reads its earlier values in `jahia-commons.encryptor.legacy.password`. Set that property to `__shipped__` to name the password this library ships, which is what an installation that ran without a password of its own stored its values under.

`jahia-commons.encryptor.algorithm` now names the algorithm that reads a value stored before the installation held a key of its own, because new values are AES-GCM whatever it says. It is renamed `jahia-commons.encryptor.legacy.algorithm`, and the earlier name keeps working. Keep either one set for as long as a value written under it is still stored: removing it makes those values unreadable whenever the algorithm was not the jasypt default.
