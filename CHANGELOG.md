# x25519-key-agreement-key-2020 Changelog

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
