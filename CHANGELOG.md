## 0.1.1 (2019-03-06)

Breaking changes:
  - (WIP) move to `jwt` gem (instead of `json-jwt`), since it has more JWT
    features covered;
  - Because of the above change, JWE (encrypted JWT) is now broken, as it's not
    re-implemented at the moment;

Features:
  - Now supports simple JWT (un)packing (the one without JWE keys, but with
    passphrased HMAC);
  - Has the ability to (un)pack only selected fields of the record;
  - Can either remove source field(s), or leave them along with the new ones.

## 0.1.0 (2017-05-07)

Features:
  - compatible with fluentd v0.14
  - change license from MIT License to Apache License Version 2.0

Deprecations:

  - deprecated support of fluentd v0.12
