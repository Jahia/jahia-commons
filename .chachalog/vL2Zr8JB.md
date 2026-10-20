---
jahia-commons: minor
---

Added key rotation for encrypted values: each value records the key that sealed it, and earlier keys stay readable.

Set `jahia-commons.encryptor.previous.1`, `jahia-commons.encryptor.previous.2` and so on, or `JAHIA_COMMONS_ENCRYPTOR_PREVIOUS_1` and so on, to the earlier keys. New values are sealed with `jahia-commons.encryptor.password`. Once no stored value carries the earlier unmarked format, set `jahia-commons.encryptor.legacy.password` to `__none__` to stop reading that format. On a cluster, add the new key as a read-only key on every node first, and make it the primary key once every node holds it. Prefer a key of 32 random bytes to a passphrase: `openssl rand -base64 32` produces one, set as `base64:` followed by its output. This version does not read values that version 1.2.0 sealed with a password of the installation's own.
