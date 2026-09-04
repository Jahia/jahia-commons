---
jahia-commons: minor
---

Changed the stored form of encrypted values so that each value records its format, and used AES-GCM for new values.

A value written by this version cannot be read by an earlier version, so take that into account before you downgrade.
