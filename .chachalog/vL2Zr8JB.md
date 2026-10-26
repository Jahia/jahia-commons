---
jahia-commons: minor
---

Added key rotation for encrypted values: each value records the key that sealed it, and earlier keys stay readable.

Set `jahia-commons.encryptor.previous.1`, `jahia-commons.encryptor.previous.2` and so on, or `JAHIA_COMMONS_ENCRYPTOR_PREVIOUS_1` and so on, to the earlier keys. New values are sealed with `jahia-commons.encryptor.password`. Earlier keys open values written by this version only. Values written before, which carry no format marker, are read with `jahia-commons.encryptor.legacy.password`, so set it to the password that wrote them, or to `__shipped__` when none was set. Startup is refused when earlier keys are set and that property is not. Once no stored value carries the earlier unmarked format, set it to `__none__` to stop reading that format.

A cluster takes a new key, its first one included, in two rolling restarts. First set the key as `jahia-commons.encryptor.next`, or `JAHIA_COMMONS_ENCRYPTOR_NEXT`, on every node: the next key reads the values sealed under it, and seals none. Once every node holds it, move it on each node to `jahia-commons.encryptor.password`, and move the key that property held, if any, to `jahia-commons.encryptor.previous.<n>`. A key named both as the next key and as the password is refused at startup. At that second step, keep `jahia-commons.encryptor.legacy.password` set: without it, its default follows the new password, and every unmarked value would then be read under the wrong key. Until `jahia-commons.encryptor.legacy.password` is set to `__none__`, a node rolled back after the second step goes back to the first one.

Each passphrase, as the primary key, the next key or a read-only key, is stretched once when the encryptor is built, which takes about half a second per key. Prefer a key of 32 random bytes, which costs nothing to build: `openssl rand -base64 32` produces one, set as `base64:` followed by its output. This version does not read values that version 1.2.0 sealed with a password of the installation's own.
