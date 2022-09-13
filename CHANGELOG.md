# [11.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.5.4...v11.0.0) (2022-09-13)


### Features

* 🎸 Return samlError from token in devicecode ([ff184f1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/ff184f1bfd19875564783456bf84e98cde1c329d))


### BREAKING CHANGES

* requires DB update

## [10.5.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.5.3...v10.5.4) (2022-09-13)


### Bug Fixes

* **deps:** update dependency io.sentry:sentry-bom to v6.4.1 ([14d76c1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/14d76c1adc6ae5b2f5295e30494064c2f40a80bb))

## [10.5.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.5.2...v10.5.3) (2022-09-13)


### Bug Fixes

* 🐛 Downgrade logback to preserve compatibility ([97b2a0d](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/97b2a0d8ac4610994500cfc1eda3d6ca818f492d))

## [10.5.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.5.1...v10.5.2) (2022-09-13)


### Bug Fixes

* **deps:** update logback.version to v1.4.0 ([7849045](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/78490450eb417166c4856238989369ca3ca20bca))

## [10.5.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.5.0...v10.5.1) (2022-08-29)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.24.3 ([fa7e1e0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/fa7e1e0ddb4b65495b0080c784e197bfe54ce95c))
* **deps:** update dependency io.sentry:sentry-bom to v6.4.0 ([20caf2a](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/20caf2ac243d7b458e77c146c4852ea35685af2b))
* **deps:** update dependency org.postgresql:postgresql to v42.5.0 ([e534f7b](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/e534f7b0c8b884aa18e64d08ac522e9061361cf2))

# [10.5.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.4.0...v10.5.0) (2022-08-26)


### Features

* return error response on noAuthnContext ([7d1f731](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/7d1f73104e123eb5b0ad87eb37bc0eb46b0e65bd))

# [10.4.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.3.4...v10.4.0) (2022-08-26)


### Features

* Integration with sentry ([219f31c](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/219f31c3fccd71f4f0754c5e2552a5d16148096a))

## [10.3.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.3.3...v10.3.4) (2022-08-24)


### Bug Fixes

* 🐛 Allow calling /devicecode without client secret ([02d8d34](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/02d8d34fb1f6dae8ba29371768fa4c5a20338a0d))

## [10.3.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.3.2...v10.3.3) (2022-08-22)


### Bug Fixes

* **deps:** update dependency org.postgresql:postgresql to v42.4.2 ([8fce861](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/8fce861d7dd4e93786cdd2778c39ef72753eb3bf))
* **deps:** update shedlock.version to v4.41.0 ([2b60811](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/2b60811a5ac7c85ce6809932d0b69786285cbf27))

## [10.3.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.3.1...v10.3.2) (2022-08-20)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.24.2 ([5bdccc7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/5bdccc7a644975191db5ec7e4c568ef386dbff5b))

## [10.3.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.3.0...v10.3.1) (2022-08-19)


### Bug Fixes

* **deps:** update dependency org.apache.directory.api:api-all to v2.1.2 ([61f49e6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/61f49e661037bfdde833afdb40c5385046db3e13))
* **deps:** update dependency org.springframework.security:spring-security-bom to v5.7.3 ([530bdb2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/530bdb262ef5c892dff30125610e7fb67c3ebe33))

# [10.3.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.2.1...v10.3.0) (2022-08-16)


### Features

* GA4GH ClaimSource by API call ([0753598](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/075359886e6c56b1ff5e3cefc2e1b12d381a4e38))

## [10.2.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.2.0...v10.2.1) (2022-08-15)


### Bug Fixes

* **deps:** update shedlock.version to v4.40.0 ([c597037](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/c597037ec98b03e034a84c55665079e73ce474cc))

# [10.2.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.1.3...v10.2.0) (2022-08-15)


### Features

* 🎸 Spring5 & Spring-security 5 ([3faa9a6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/3faa9a68ba64c93558644d31e80f42c39cc38fd5))

## [10.1.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.1.2...v10.1.3) (2022-08-15)


### Bug Fixes

* **deps:** update eclipse-persistence.version to v2.7.11 ([d85ea1c](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/d85ea1cb9600ec484c4347cc77737763e6de253d))

## [10.1.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.1.1...v10.1.2) (2022-08-08)


### Bug Fixes

* **deps:** update dependency org.apache.directory.api:api-all to v2.1.1 ([741e502](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/741e5027cc82d8fc282f716f760baf7cb5414fa3))

## [10.1.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.1.0...v10.1.1) (2022-08-08)


### Bug Fixes

* **deps:** update dependency com.google.code.gson:gson to v2.9.1 ([9b42b50](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9b42b50cc92d775eab13d3cbd8719d9ac16cf6dc))
* **deps:** update dependency org.mariadb.jdbc:mariadb-java-client to v3.0.7 ([c27a5c5](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/c27a5c58bc8428c97a57f50292a640455807c34d))

# [10.1.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.0.3...v10.1.0) (2022-07-28)


### Features

* 🎸 Configurable timeouts in RPC connector ([a929858](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/a929858026de152e8c33c2819f551302b292a443))

## [10.0.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.0.2...v10.0.3) (2022-07-27)


### Bug Fixes

* correct postgreSQL for v10 breaking change ([28a9411](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/28a9411af439608ebe43b5b332cf4bb29569c652))
* **deps:** update dependency mysql:mysql-connector-java to v8.0.30 ([5426aa9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/5426aa9835463c748506004664e24791c8d76d67))

## [10.0.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.0.1...v10.0.2) (2022-07-25)


### Bug Fixes

* 🐛 Fix nullPointerexception in AuthProcFilterInit ([64c0d51](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/64c0d510597382f3257ed98424fdc239b6e33fd6))

## [10.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v10.0.0...v10.0.1) (2022-07-13)


### Bug Fixes

* 🐛 Fix script loading for LS footer ([bd90a76](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/bd90a763888d91e1b29449612503b8e2ce9b93d1))

# [10.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.4.0...v10.0.0) (2022-07-09)


### Bug Fixes

* 🐛 Fix displaying for consent for EMBL ([ef47df1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/ef47df163f76a10e8d504b4068c20d1204e7d048))


### BREAKING CHANGES

* 🧨 DB changes (see v10.0.0.sql files)

# [9.4.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.3.2...v9.4.0) (2022-07-08)


### Features

* IsEligible authproc filter and claim source ([2e0aaa7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/2e0aaa772bb063260b6b4abbf3919b01c7320df9))

## [9.3.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.3.1...v9.3.2) (2022-07-04)


### Bug Fixes

* **deps:** update dependency org.mariadb.jdbc:mariadb-java-client to v3.0.6 ([fc02c8f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/fc02c8f79c9b034ab8f2eff929f183f52bb120ed))

## [9.3.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.3.0...v9.3.1) (2022-06-15)


### Bug Fixes

* **deps:** update dependency org.postgresql:postgresql to v42.4.0 ([9f56413](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9f56413f05854b9a093ca4c324d5429a8a13fbfe))

# [9.3.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.2.2...v9.3.0) (2022-06-03)


### Features

* 🎸Claim sources for extracting AuthenticationContextClassRef and AuthnInstant ([d9d3034](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/d9d3034e552676353db30eb3066b56e0d78c6bfc))

## [9.2.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.2.1...v9.2.2) (2022-06-03)


### Bug Fixes

* 🐛 Fix SAML Claim source when singleValue to use joiner ([d16c3c6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/d16c3c6368a4039ac6918f8a68960bfaac899dab))
* 🐛 Fixed displaying consent screens for LS template ([9884eb1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9884eb1f0ee1a400b8d6ca285390801ed12086e9))

## [9.2.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.2.0...v9.2.1) (2022-06-01)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.23 ([0c465ca](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/0c465ca1ff2ef4bbfd331cf35532a6d9fd30cf96))

# [9.2.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.6...v9.2.0) (2022-05-30)


### Bug Fixes

* **deps:** update dependency org.mariadb.jdbc:mariadb-java-client to v3.0.5 ([e6a8342](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/e6a834243896443f8495af1dab9a560ef8ba4d6e))
* **deps:** update dependency org.postgresql:postgresql to v42.3.6 ([c1d62ca](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/c1d62ca98ec137898e7363713493c28f2d44b496))


### Features

* Added new claims sources ([15cf3a9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/15cf3a95eb0f62e4fc4be7f2a1e791683ca189cb))

## [9.1.6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.5...v9.1.6) (2022-05-23)


### Bug Fixes

* **deps:** update dependency com.fasterxml.jackson.dataformat:jackson-dataformat-yaml to v2.13.3 ([e5f3a62](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/e5f3a629807630aba823ca313a7573b2cc8010ec))

## [9.1.5](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.4...v9.1.5) (2022-05-09)


### Bug Fixes

* **deps:** update dependency org.postgresql:postgresql to v42.3.5 ([319d0c7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/319d0c7c2a190c20889768668b6d702cab796cea))

## [9.1.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.3...v9.1.4) (2022-04-25)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.22 ([1a087e4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/1a087e4ba1da9ef89d5315a09bd41e4acc591c21))

## [9.1.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.2...v9.1.3) (2022-04-25)


### Bug Fixes

* **deps:** update dependency org.springframework.security.oauth:spring-security-oauth2 to v2.5.2.release ([5eafd46](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/5eafd46d0a53a2bdb88b0cb2086e0fface4022be))

## [9.1.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.1...v9.1.2) (2022-04-25)


### Bug Fixes

* **deps:** update dependency mysql:mysql-connector-java to v8.0.29 ([9ff89f7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9ff89f78f8571e7becd8d9391b788ee035298a57))

## [9.1.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.1.0...v9.1.1) (2022-04-22)


### Bug Fixes

* 🐛 Fixed wrong mail in LS consent ([c84912c](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/c84912c55106b5b272e5221efbacdbd1451aeb7e))

# [9.1.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.0.3...v9.1.0) (2022-04-22)


### Features

* 🎸 Filter for logging authentication details ([585dbd8](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/585dbd82a5364e5ca9fe16a9b5714aa340f47896))

## [9.0.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.0.2...v9.0.3) (2022-04-22)


### Bug Fixes

* **deps:** update dependency org.projectlombok:lombok to v1.18.24 ([6736cf4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/6736cf4c38adad8b37e8c9914348da938c69506c))
* improve MUNI header ([3f0f910](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/3f0f9103d8223ff41476f04e6c6a034a483da84f))

## [9.0.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.0.1...v9.0.2) (2022-04-20)


### Bug Fixes

* MUNI branding ([07479e4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/07479e4a04fdbbee2a14c22739957d43d12e49c2))

## [9.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v9.0.0...v9.0.1) (2022-04-19)


### Bug Fixes

* **deps:** update dependency org.postgresql:postgresql to v42.3.4 ([cae6002](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/cae60026d32814e814ac76c8dd1a5b867a358e77))

# [9.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.5...v9.0.0) (2022-04-13)


### Features

* LS AAI design ([cd1ce6f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/cd1ce6fcc2706d77f01c655b969b597c7f692f49))


### BREAKING CHANGES

* requires database update (see migraiton script),
dropped ELIXIR theme

## [8.2.5](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.4...v8.2.5) (2022-04-11)


### Bug Fixes

* show unapproved message ([0d6e2c7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/0d6e2c70d8b9bc34f0e1a77a9af996966c72f2e5))

## [8.2.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.3...v8.2.4) (2022-04-11)


### Bug Fixes

* 🐛 Added missing return values when RPC disabled ([733597a](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/733597a4731dc840520672f344f55a290237e988))

## [8.2.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.2...v8.2.3) (2022-04-11)


### Bug Fixes

* 🐛 Fix nullPointer in SamlAuthenticationDetailsStringCon ([3c034f4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/3c034f4c54965aa44fa654daf90520e5aa3f6a46))

## [8.2.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.1...v8.2.2) (2022-04-06)


### Bug Fixes

* 🐛 Fix storing SavedUserAuth ([c83ecc2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/c83ecc28e20ed44da21b7c3b9172f0cda5a50d12))

## [8.2.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.2.0...v8.2.1) (2022-04-04)


### Bug Fixes

* 🐛 Remove RelayState from SAML details in SavedUserAuth ([0f73d88](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/0f73d882363d1d5adb2bcf464f55339614947ff2))

# [8.2.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.9...v8.2.0) (2022-04-04)


### Features

* 🎸 More user lookup methods ([3ea2b82](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/3ea2b82053651a331c015b774ce69107f679ecd9))

## [8.1.9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.8...v8.1.9) (2022-04-04)


### Bug Fixes

* **deps:** update dependency org.aspectj:aspectjweaver to v1.9.9.1 ([fb56956](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/fb5695632497b257955a9d72a8d2a83cda65b5a8))

## [8.1.8](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.7...v8.1.8) (2022-03-31)


### Bug Fixes

* **deps:** update dependency org.aspectj:aspectjweaver to v1.9.9 ([4ef0063](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/4ef006308a23111f9270b6d3c6b86d6c1f0f174f))
* **deps:** update dependency org.mariadb.jdbc:mariadb-java-client to v3.0.4 ([96358d9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/96358d989b46618a048e71fdce310ce11ac807ce))

## [8.1.7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.6...v8.1.7) (2022-03-23)


### Bug Fixes

* **deps:** update eclipse-persistence.version to v2.7.10 ([2f864fc](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/2f864fca1cdfe2affec8602f8525f30a26d63565))

## [8.1.6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.5...v8.1.6) (2022-03-23)


### Bug Fixes

* 🐛 Allow Group description to be empty string ([76899b4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/76899b44777160ec8c12c682af4e940388a72c60))
* **deps:** update dependency com.fasterxml.jackson.dataformat:jackson-dataformat-yaml to v2.13.2 ([1db9d51](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/1db9d5113a629f893817c08385909729b2819580))

## [8.1.5](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.4...v8.1.5) (2022-03-09)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.21 ([b1810d8](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/b1810d82baff39ba912fbb8619c2e4fd5ff027e4))

## [8.1.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.3...v8.1.4) (2022-03-09)


### Bug Fixes

* **deps:** update logback.version to v1.2.11 ([8601f9c](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/8601f9c8724135a5d89f7eed2726bceaec898246))

## [8.1.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.2...v8.1.3) (2022-03-09)


### Bug Fixes

* **deps:** update dependency com.google.guava:guava to v31.1-jre ([1032ed0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/1032ed065ac5e45d51f3dd8520e535b97a43ec63))

## [8.1.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.1...v8.1.2) (2022-02-17)


### Bug Fixes

* 🐛 Fix missing execute statement in statistics filter ([93b8081](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/93b8081c330419d339a3c7a520df8047c453b578))

## [8.1.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.1.0...v8.1.1) (2022-02-17)


### Bug Fixes

* **deps:** update dependency com.google.code.gson:gson to v2.9.0 ([0ec65b6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/0ec65b6eeed09fbe5a1c77a17b0e0e278b8a3354))

# [8.1.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.6...v8.1.0) (2022-02-17)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.19 ([bb1443f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/bb1443fd9e838895061543b3376580fbee7acaf0))
* **deps:** update dependency org.aspectj:aspectjweaver to v1.9.8 ([78087dc](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/78087dc71621c49d0081b812b8c3bd193907ef1b))
* **deps:** update dependency org.postgresql:postgresql to v42.3.3 ([9810e84](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9810e84915abe429cacf5e91f431115c19cb9e6c))


### Features

* 🎸 Display noAuthnContext message on login_failure ([8872469](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/8872469c197639ef445878ba34b61ee754f06bad))

## [8.0.6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.5...v8.0.6) (2022-02-01)


### Bug Fixes

* **deps:** update dependency com.nimbusds:nimbus-jose-jwt to v9.18 ([6653cdb](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/6653cdbfe0f9cc073fc62b4d5eca5e9d5778400c))

## [8.0.5](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.4...v8.0.5) (2022-02-01)


### Bug Fixes

* **deps:** update dependency org.mariadb.jdbc:mariadb-java-client to v3 ([b3ddb12](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/b3ddb12e8daa6f46f8d64bed709775037f4c58c8))

## [8.0.4](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.3...v8.0.4) (2022-02-01)


### Bug Fixes

* **deps:** update dependency org.glassfish.jaxb:jaxb-runtime to v2.3.6 ([64f8997](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/64f899708f13d9b23f1eac65cdae5dba3e71dd24))

## [8.0.3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.2...v8.0.3) (2022-01-26)


### Bug Fixes

* 🐛 Consider empty referer as external ([d4bc19e](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/d4bc19e2d8e8a9750c71ad8065fd26a97704da80))

## [8.0.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.1...v8.0.2) (2022-01-13)


### Bug Fixes

* 🐛 Set email verified to true ([93fc557](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/93fc5577f57d7102c2c29f4fdd6087751a60e60b))

## [8.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v8.0.0...v8.0.1) (2022-01-12)


### Bug Fixes

* 🐛 Fix missing sub in ClaimSourceProduceContext ([5eace9f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/5eace9fb21fce78e8e05e1b4eba8e47143f88c49))

# [8.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.5.2...v8.0.0) (2022-01-12)


### Features

* 🎸 Refactored userinfo serv., new SAML-based claim sources ([2c413d9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/2c413d9916e8a862d91a3be93490bed832245c70))


### BREAKING CHANGES

* 🧨 requires database update

## [7.5.2](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.5.1...v7.5.2) (2022-01-10)


### Bug Fixes

* 🐛 Do not display remember me when prompt=consnet ([1bf72b8](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/1bf72b802ade1f04e35c55061615895ccb435c48))

## [7.5.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.5.0...v7.5.1) (2021-12-23)


### Bug Fixes

* incorrect label on stay logged in button ([75a626f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/75a626f9daa0a58fc58f03307574b09a5ac17849))

# [7.5.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.4.1...v7.5.0) (2021-12-10)


### Features

* 🎸 Configurable favicons ([bf227df](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/bf227df26e364a61c3ba08d122e8bccdbcc9184c))

## [7.4.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.4.0...v7.4.1) (2021-12-09)


### Bug Fixes

* 🐛 Fix inserting and reading properties in the stats filter ([31710bf](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/31710bf5f5b14009904ec38c88e7a8e80a8d9d8d))

# [7.4.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.3.0...v7.4.0) (2021-12-09)


### Features

* 🎸 Configurable name of user col in stats filter ([4a5be5d](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/4a5be5d32baf754d6550747cba30fb1a8ec355fb))

# [7.3.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.2.0...v7.3.0) (2021-12-09)


### Features

* 🎸 Configurable max pool size for JDBC data sources ([e5b406e](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/e5b406e85311166a6e9c54ec0d4d52637557746b))

# [7.2.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.1.1...v7.2.0) (2021-12-08)


### Features

* 🎸 Added automated bundling of .war file into release ([cd1118f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/cd1118f1a0c8121fd49fe73b70b6074ea1ce4a0c))

## [7.1.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.1.0...v7.1.1) (2021-12-08)


### Bug Fixes

* 🐛 Fix possible SQL exceptions ([b3bd9e9](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/b3bd9e94c76b7781a31d362fe8fda61242b30d83))

# [7.1.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v7.0.0...v7.1.0) (2021-12-07)


### Bug Fixes

* DB inserts in statistics work with PostgreSQL ([b72eb8f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/b72eb8fd8e4633205c86e1861f6acb7558ac62de))


### Features

* Added configurable ipdIdColumnName and spIdColumnName in statistics ([515f99b](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/515f99b25518d6e8be66a0c50133c01216c0bde5))

# [7.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v6.0.0...v7.0.0) (2021-12-06)


### Code Refactoring

* 💡 Refactored GA4GH Passports and visas ([a94fd99](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/a94fd992dd5889745b93b25e2d17460569688c16))


### Features

* 🎸 Implemented BBMRI-ERIC Ga4gh Passports and Visas ([141e6c8](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/141e6c8653112e1b3b0beda2ea3ba8be3eca4bca))


### BREAKING CHANGES

* 🧨 Ga4gh Claim source class for ELIXIR has been changed. Also, the
ElixirAccessTokenModifier class has been moved and renamed.

# [6.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v5.0.1...v6.0.0) (2021-12-06)


### Code Refactoring

* 💡 Drop support for java 8 ([4a0b63e](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/4a0b63ec0e67c519cd9c0af79c8224777761090b))


### BREAKING CHANGES

* 🧨 Dropped support for java 8

## [5.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v5.0.0...v5.0.1) (2021-12-02)


### Bug Fixes

* 🐛 Fix fallbacking of locale to the code to prevent errors ([ceb01c7](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/ceb01c78e760e32e803be30c559e772323bd68cb))

# [5.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v4.0.1...v5.0.0) (2021-11-30)


### Code Refactoring

* 💡 Refactored how translations are loaded and used ([665b45f](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/665b45fb419a7dedc20de62ec0e1c6d550b7f3bd))


### BREAKING CHANGES

* Property `web.langs.customfiles.path` must point to the
RersourceBundle.

## [4.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v4.0.0...v4.0.1) (2021-11-19)


### Bug Fixes

* 🐛 Fixed missing ACRs code and device_code flows ([4d3b072](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/4d3b07225c1f7b1abb7a9c79d170326fa81c2aa8))

# [4.0.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.5.0...v4.0.0) (2021-11-19)


### Bug Fixes

* 🐛 Fix ACR for implicit and authorization_code flows ([39bc00a](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/39bc00a3b08e3129e2244f123a466f4c9490ae36))


### BREAKING CHANGES

* 🧨 Database needs to be updated: `ALTER TABLE saved_user_auth DROP
source_class; ALTER TABLE saved_user_auth ADD COLUMN acr VARCHAR(1024);`

# [3.5.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.4.1...v3.5.0) (2021-11-16)


### Features

* 🎸 AARC_IDP_HINTING implemented ([ebd1459](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/ebd1459ba3eac20717c80955c5dbc725fd3934f8))

## [3.4.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.4.0...v3.4.1) (2021-11-15)


### Bug Fixes

* 🐛 Added missing PostgreSQL dependency ([e12c164](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/e12c164b46cbf9efb1a3516cb8c03e307e7049c2))

# [3.4.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.3.0...v3.4.0) (2021-11-12)


### Features

* 🎸 Forward client_id in AuthenticationContextClass ([6a6d1e3](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/6a6d1e3ad92d3c6785f0e786aaf4c3fa5f04b806))

# [3.3.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.2.0...v3.3.0) (2021-11-11)


### Features

* 🎸 Extended list of internal referrers for sess. invalider ([9aa16ff](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/9aa16ffe5cb1c1b045d9f1f71cd94751d9d876b4))
* 🎸 Make SAML identifier attribute configurable ([3949857](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/39498573c3d62284298bae0df48fbbcf071e9caf))

# [3.2.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.1.0...v3.2.0) (2021-11-09)


### Features

* 🎸 Adderd e-INFRA CZ template ([5eb50f6](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/5eb50f64414db6a42cff76003c5b41f4e8e03535))

# [3.1.0](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.0.1...v3.1.0) (2021-11-08)


### Features

* 🎸 Sign refresh tokens ([23a6354](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/23a6354fc708bd89301bf2cac0619bbebb431f4f))

## [3.0.1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/compare/v3.0.0...v3.0.1) (2021-11-05)


### Bug Fixes

* 🐛 fix loading JWKS ([371adc1](https://github.com/CESNET/OpenID-Connect-Java-Spring-Server/commit/371adc13fbff6150a32fcd8b5242ef03899c758b))

Unreleased:

*1.3.3*:
- Authorization codes are now longer
- Client/RS can parse the "sub" and "user_id" claims in introspection response
- Database-direct queries for fetching tokens by user (optimization)
- Device flow supports verification_uri_complete (must be turned on)
- Long scopes display properly and are still checkable
- Language system remebers when it can't find a file and stops throwing so many errors
- Index added for refresh tokens
- Updated to Spring Security 4.2.11
- Updated Spring to 4.3.22
- Change approve pages to use issuer instead of page context
- Updated oracle database scripts

*1.3.2*:
- Added changelog
- Set default redirect URI resolver strict matching to true
- Fixed XSS vulnerability on redirect URI display on approval page
- Removed MITRE from copyright
- Disallow unsigned JWTs on client authentication
- Upgraded Nimbus revision
- Added French translation
- Added hooks for custom JWT claims
- Removed "Not Yet Implemented" tag from post-logout redirect URI

*1.3.1*:
- Added End Session endpoint
- Fixed discovery endpoint
- Downgrade MySQL connector dependency version from developer preview to GA release

*1.3.0*:
- Added device flow support
- Added PKCE support
- Modularized UI to allow better overlay and extensions
- Modularized data import/export API
- Added software statements to dynamic client registration
- Added assertion processing framework
- Removed ID tokens from storage
- Removed structured scopes

*1.2.6*: 
- Added strict HEART compliance mode
