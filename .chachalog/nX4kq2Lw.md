---
jahia-commons: minor
---

Added `EncryptorKeys` and `EncryptionUtils.initializeEncryptor(EncryptorKeys, boolean)`, for an application that resolves its keys itself. The encryptor holds the keys named in the object and no other, and reads no configuration. The object requires the legacy password: set it to `__shipped__` for the password this library ships, to the earlier password, or to `__none__`. A blank key is refused. The earlier `initializeEncryptor` methods keep reading the next key and the read-only keys from the configuration.
