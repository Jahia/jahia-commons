# jahia-commons Changelog

## 0.1.0

### New Features

* Changed the stored form of encrypted values so that each value records its format, and used AES-GCM for new values.

  Once `jahia-commons.encryptor.password` names a key of this installation's own, a value written by this version cannot be read by an earlier version, so take that into account before you downgrade. An installation that sets no such password keeps writing the earlier format.

  An installation that sets an encryption password of its own names the key that reads its earlier values in `jahia-commons.encryptor.legacy.password`. Set that property to `__shipped__` to name the password this library ships, which is what an installation that ran without a password of its own stored its values under.

  `jahia-commons.encryptor.algorithm` now names the algorithm that reads a value stored before the installation held a key of its own, because new values are AES-GCM whatever it says. It is renamed `jahia-commons.encryptor.legacy.algorithm`, and the earlier name keeps working. Keep either one set for as long as a value written under it is still stored: removing it makes those values unreadable whenever the algorithm was not the jasypt default.

* Added key rotation for encrypted values: each value records the key that sealed it, and earlier keys stay readable.

  Set `jahia-commons.encryptor.previous.1`, `jahia-commons.encryptor.previous.2` and so on, or `JAHIA_COMMONS_ENCRYPTOR_PREVIOUS_1` and so on, to the earlier keys. New values are sealed with `jahia-commons.encryptor.password`. Earlier keys open values written by this version only. Values written before, which carry no format marker, are read with `jahia-commons.encryptor.legacy.password`, so set it to the password that wrote them, or to `__shipped__` when none was set. Startup is refused when earlier keys are set and that property is not. Once no stored value carries the earlier unmarked format, set it to `__none__` to stop reading that format. An installation that ran without a password and sets its first one must set `jahia-commons.encryptor.legacy.password` to `__shipped__` in the same step: left unset, it follows the new password, and none of the earlier values can be read. A warning is now logged whenever `jahia-commons.encryptor.password` is set and that property is not.

  On a cluster, set the new key as `jahia-commons.encryptor.next`, or `JAHIA_COMMONS_ENCRYPTOR_NEXT`, on every node first, with `jahia-commons.encryptor.legacy.password` set to the password that wrote the values carrying no marker, or to `__shipped__` when none was set. Startup is refused when the next key is set and that property is not. The next key opens values and seals none, so new values keep their format until it is promoted. Once every node holds it, move it to `jahia-commons.encryptor.password` node by node, and move the key it replaces to `jahia-commons.encryptor.previous.1`. A node rolled back after this step returns to the first one, with the key still in `jahia-commons.encryptor.next`. Keep `jahia-commons.encryptor.legacy.password` set after the promotion, until no value carrying no marker is left and it can be set to `__none__`: without it, those values are read under the new key. To abandon a next key after a node was promoted under it, move it to `jahia-commons.encryptor.previous.<n>` rather than remove it, so that a reseal moves its values back under the primary key. Startup is refused when the next key is also the primary key.

  Each passphrase, as the primary key, the next key or a read-only key, is stretched once when the encryptor is built, which takes about half a second per key. Prefer a key of 32 random bytes, which costs nothing to build: `openssl rand -base64 32` produces one, set as `base64:` followed by its output. This version does not read values that version 1.2.0 sealed with a password of the installation's own.

### Bug Fixes

* Added maven.jahia.com to the Maven repositories jahia-commons uses to download its dependencies.
