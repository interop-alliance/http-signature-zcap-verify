# @interop/http-signature-zcap-verify ChangeLog

## 13.1.0 - TBD

### Added

- `verifyCapabilityInvocation` accepts an optional async `dereferenceTarget`
  hook, passed to `CapabilityInvocation` (requires `@interop/zcap` 12.1.0). It
  maps the invoked capability's target before the comparison with the request
  URL.

## 13.0.0 - 2026-11-17

### Changed

- **BREAKING**: Update to `@interop/zcap@12.0.0`. Verification fails with an
  `UnsupportedCaveatError` when any capability in the chain carries a `caveat`
  with no handler in `supportedCaveats`. Previously the property was ignored.
- **BREAKING**: Verification refuses a capability with a malformed `caveat`, or
  with a property name that contains `:` or starts with `@` outside `proof`.
- **BREAKING**: Verification refuses a delegated capability that lists a
  `@context` URL other than the zcap context, the context of `suite`, or a URL
  in `allowedContexts`.
- Update to `@interop/data-integrity-core@8.12.0`.

### Added

- `supportedCaveats`, `allowedContexts` and `maxCaveats` options on
  `verifyCapabilityInvocation`, passed through to `@interop/zcap`.
- `caveats` on a successful result. It lists each caveat found in the chain
  with the capability that carries it.

## 12.2.7 - 2026-10-24

### Changed
- Update to latest zcap (export isValidTarget).

## 12.2.6 - 2026-10-12

### Changed
- Update to latest jsigs and di core.

## 12.2.5 - 2026-10-06

### Changed
- Update to latest `@interop/jsonld-signatures@11.8.7`.

## 12.2.4 - 2026-09-25

### Changed
- Update to latest `@interop/data-integrity-core@8.8.0`.

## 12.2.3 - 2026-09-16

### Changed

- Update to latest `zcap` spec (empty chain guard).

## 12.2.2 - 2026-08-27

### Changed

- Update to latest `http-signature-header` and `security-document-loader`.

## 12.2.1 - 2026-08-18

### Changed
- Update to latest `@interop/data-integrity-core@8.7.1`.

## 12.2.0 - 2026-07-22

### Added

- Export `decodeEmbeddedCapability()`, the decoder for the
  `Capability-Invocation` header's embedded `capability` parameter
  (`base64url(gzip(json))`), so consumers can inspect a submitted capability
  chain without running the full verification. The internal decode path now
  uses it.

## 12.1.2 - 2026-07-17

### Fixed
- Update to `@interop/data-integrity-core@8.3.0` and related.

## 12.1.1 - 2026-06-28

### Fixed
- Update to latest zcap and d-i-core deps.

## 12.1.0 - 2026-06-25

Matches upstream `@digitalbazaar/http-signature-zcap-verify@11.2.0`.

### Changed
- The invocation target `url` is now treated as absolute for **any** URI scheme,
  not just `https:`/`http:`. An absolute `url` (e.g. `did:`, `urn:`) is used as
  the invocation target verbatim; only a relative `url` (no leading scheme) is
  resolved against the request host as `https://${host}${url}`. This enables
  DID-relative invocation targets. Scheme detection uses the RFC 3986 scheme
  grammar, so non-conformant relative URLs that carry an unencoded colon in a
  path segment (e.g. `/foo:bar`) are still treated as relative.

## 12.0.4 - 2026-06-13

### Changed
- Update to latest dependencies, including `@interop/data-integrity-core@8`,
  `@interop/zcap@11.0.3`.

## 12.0.3 - 2026-06-09

### Changed
- Update to latest dependencies, including `@interop/data-integrity-core@7`,
  `@interop/ed25519-verification-key@8` (whose `export()` is now async), and
  `@interop/zcap@11.0.2`.

## 12.0.2 - 2026-06-02

### Changed
- Update to work with latest `@interop/zcap@11.0.1` (which was converted to
  TypeScript).
- Type the `suite` option as the new exported `SignatureSuite` type (derived
  from `@interop/zcap`'s `CapabilityInvocationOptions`) instead of `object`, to
  match the suite type that `CapabilityInvocation` now expects.
- Read `dereferencedChain` directly from the `CapabilityInvocation.validate()`
  result now that it is part of the public `CapabilityValidateResult` type,
  removing the previous internal cast.

## 12.0.1 - 2026-06-01

### Changed
- Use exported types from `@interop/data-integrity-core` instead of re-defining
  locally.

## 12.0.0 - 2026-06-01

### Changed
- **BREAKING**: Fork, rename package to `@interop/http-signature-zcap-verify`.
- **BREAKING**: Rewrite in TypeScript; now ships ESM from `dist/` with type
  declarations. Source moved from `lib/` to `src/`.
- **BREAKING**: Switch dependencies to the `@interop` forks:
  `@digitalbazaar/http-signature-header` to `@interop/http-signature-header`,
  `@digitalbazaar/zcap` to `@interop/zcap`.
- Replace `base64url-universal` and the Node/browser `base64Decode` split with
  `@scure/base` (isomorphic). The `signature` parameter is decoded as padded
  standard base64; the `capability-invocation` capability as unpadded base64url.

## 11.1.1 - 2024-04-02

### Fixed
- Fixed an issue where verification would fail if a relative url
  containing an unencoded colon was passed to create the
  `invocationTarget`. This allows URLs with colons that are not
  properly encoded (failing to encode colons is bad practice
  and non-conformant) because they are still often allowed in
  applications.

## 11.1.0 - 2022-11-13

### Changed
- Update dependencies:
  - Use `@digitalbazaar/zcap@9`.

## 11.0.0 - 2022-06-07

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- Update dependencies.
- Remove unused dependencies.
- Lint module.

## 10.2.0 - 2022-05-12

### Added
- Add optional `beforeValidatePurpose` method for inspecting the proof purpose,
  proof meta data, and capability information prior to purpose validation. This
  function can be useful for handling situations where the root controller for
  the target object may be cached and could have changed -- and the information
  passed could help an application determine whether or not it should check for
  a more fresh root controller.

## 10.1.0 - 2022-01-14

### Added
- Use zcap@7.1 to include `dereferencedChain` in verification results.

## 10.0.0 - 2022-01-11

### Changed
- **BREAKING**: Renamed package to `@digitalbazaar/http-signature-zcap-verify`.
- Updated dependencies.

## 9.0.1 - 2022-01-11

### Fixed
- Use http-signature-zcap-invoke@4 dev dependency.

## 9.0.0 - 2022-01-11

### Added
- Add optional parameters `maxChainLength`, `maxClockSkew`, and
  `maxDelegationTtl` to allow for more fine grained control. These
  parameters all have defaults in zcapld that could previously not be set to
  other values at this layer.

### Changed
- **BREAKING**: A new function parameter `getVerifier` must now be passed. This
  function will be given the `keyId` for the key to be used to verify a
  signature and the `documentLoader` passed to `verifyCapabilityInvocation`. It
  must return a `verifier` and a `verificationMethod`. The `verifier` object
  must have a `verify` function that can be called with `data` and a
  `signature` and that returns a boolean. The `verificationMethod` object
  must include a verification method expressing the key information. The
  `getVerifier` function may throw an exception if the key is revoked. This
  new `getVerifier` function allows specific cryptographic suites to be
  decoupled from this library and, as such, the crypto-ld and ed25519 libraries
  are no longer dependencies of this library.

### Removed
- **BREAKING**: The `getInvokedCapability` parameter has been removed as it is
  no longer needed.

## 8.2.0 - 2021-08-19

### Added
- Allow `now` to be passed as a JS Date instance.

## 8.1.1 - 2021-07-21

### Fixed
- Ensure that zcap context is included in proof.

## 8.1.0 - 2021-07-11

### Changed
- Use zcapld@5.1.x, which brings in DID document-based optimizations.

## 8.0.0 - 2021-07-10

### Changed
- **BREAKING**: Updated ed25519 signature and key libraries to new major versions
  that address problems with key formats. These changes are not backwards compatible;
  systems updating this library will only be able to verify invocations from properly
  formatted keys.

## 7.2.1 - 2021-07-23

### Changed
- Backport fix to work with zcapld@5.

## 7.2.0 - 2021-07-02

### Changed
- Update to zcapld@5.x.

## 7.1.0 - 2021-05-04

### Changed
- Remove `jsonld-signatures@8.0` dependency.
- Update deps in test and fix tests.

## 7.0.0 - 2021-04-26

### Changed
- **BREAKING**: Use [`@digitalbazaar/zcapld@4.0`](https://github.com/digitalbazaar/zcapld/blob/main/CHANGELOG.md).
  - Uses new ZCAP context.

## 6.0.0 - 2021-04-06

### Changed
- **BREAKING**: Use `@digitalbazaar/zcapld@3.0` instead of `ocapld@v2.0`.
  `zcapld` required Node.js >= 12.
- **BREAKING**: Node.js >= 12 is now required.

## 5.0.0 - 2021-04-01

### Changed
- **BREAKING**: Only support `Ed25519Signature2020` proofs.
- Use `crytold@5`.

## 4.0.0 - 2021-03-02

### Changed
- **BREAKING**: Use `http-signature-header@2`.
- **BREAKING**: Use Unix time stamps (seconds since epoch) instead of ms since
  epoch.

### Added
- Parameter `now` to `verifyCapabilityInvocation` API.

## 3.0.0 - 2020-04-02

### Changed
- **BREAKING**: Use ocapld@2.

## 2.0.0 - 2020-02-19

### Changed
- **BREAKING**: Do not wrap errors in a 'NotAllowedError'.

## 1.3.0 - 2020-02-14

### Changed
- Use jsonld-signatures@5.
- Improve test coverage.

## 1.2.1 - 2020-02-11

### Fixed
- Add missing import for `TextDecoder`.

## 1.2.0 - 2020-02-10

### Added
- Add support for an `inspectCapabilityChain` handler in
  `verifyCapabilityInvocation`. This handler can be used to find revocations
  in the capability chain.
- Add support for a capability embedded in the header. The capability must be
  encoded as a JSON string that is compressed using gzip and then base64url
  endcoded.

## 1.1.0 - 2020-02-05

### Changed
- Use jsonld@2.0.2.

## 1.0.3 - 2020-02-05

### Fixed
- Return value from base64Decode helper.

## 1.0.2 - 2019-11-25

### Fixed
- Fix typo with verification method resolver frame.

## 1.0.1 - 2019-11-25

### Fixed
- Do not embed `controller` when resolving verification method.

## 1.0.0 - 2019-08-02

## 0.1.0 - 2019-08-02

### Added
- Add core files.

- See git history for changes previous to this release.
