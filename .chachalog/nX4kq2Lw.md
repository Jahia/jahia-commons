---
jahia-commons: minor
---

Added a way for an application to pass every key of the encryptor itself, with no configuration read.

The application names the legacy password too: `__shipped__` for the password this library ships, the earlier password, or `__none__`. Each refusal and warning then names a key by its role, such as the next key, and not by a property.
