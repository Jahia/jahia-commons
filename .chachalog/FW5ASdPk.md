---
jahia-commons: minor
---

Changed the stored form of encrypted values so that each value records its format, and used AES-GCM for new values.

A value written by this version cannot be read by an earlier version, so take that into account before you downgrade.

An installation that sets an encryption password of its own names the key that reads its earlier values in `jahia-commons.encryptor.legacy.password`. Set that property to `default` to name the password this library ships, which is what an installation that ran without a password of its own stored its values under.
