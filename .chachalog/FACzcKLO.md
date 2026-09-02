---
jahia-commons: patch
---

Hardened the encryption of stored values: newly encrypted data uses AES-GCM with a key derived by PBKDF2.

Existing encrypted data stays readable after the upgrade, so no migration is required. Data encrypted by this version cannot be read by an earlier version, so take that into account before you downgrade. To keep the previous encryption format for new data, set the `jahia-commons.encryptor.algorithm` property.
