# x25519-key-agreement-key-2020 Changelog

## 3.0.1 - 2022-09-04

### Changed
- Replace internal ed25519 => x25519 conversion implementation such
  that only tweetnacl is used, allowing for `ed2curve` dependency to
  be removed.

## 3.0.0 - 2022-06-02

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- Update dependencies.
- Lint module.

## 2.1.0 - 2022-05-06

### Changed
- Use `@noble/ed25519` to convert public ed25519 keys to x25519.

## 2.0.0 - 2021-06-19

### Changed
- **BREAKING**: Upgrade to @digitalbazaar/ed25519-verification-key-2020@3
  which changes the key format to multicodec.

## 1.2.1 - 2021-05-06

### Fixed
- Fix `package.json` browser section alias for `crypto.js` (was causing
  downstream webpack errors).

## 1.2.0 - 2021-04-02

### Added
- Add `includeContext` flag to `export()`.

## 1.1.0 - 2021-04-02

### Added
- Add `revoked` export tests, `SUITE_CONTEXT` class property. (To support
  `CryptoLD`'s new `fromKeyId()` method.)

## 1.0.0 - 2021-03-30

### Added
- Initial commit.
