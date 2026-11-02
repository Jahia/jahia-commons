---
jahia-commons: patch
---

`EncryptionUtils.initializeEncryptor` now takes an empty string as the next key to name none, and then leaves `jahia-commons.encryptor.next` and `JAHIA_COMMONS_ENCRYPTOR_NEXT` unread. An application that resolves its keys itself passes it, so a next key it left out does not come back from the configuration. A null next key still reads the configuration.
