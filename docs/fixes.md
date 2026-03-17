# Fixes included

This repository includes the fixes discovered during lab hardening:

- PKCS#11 **RW sessions** for write operations (key generation, cert write, signing)
- Store X.509 certificate objects in SoftHSM2 with required attributes:
  `SUBJECT`, `ISSUER`, `SERIAL_NUMBER`, `VALUE`
- Timezone-safe X.509 validity checks (naive vs aware datetime)
- Signing is performed **inside an open PKCS#11 session** (fixes `SessionHandleInvalid`)
- Enroll always **re-issues** signer certificate so CN updates correctly
- API returns JSON on errors; UI displays readable error messages
