# Agent Guidelines

## Toolchain & Project Layout

### Package Manager

Use `pnpm` (not `npm` or `yarn`). The lockfile is `pnpm-lock.yaml`. Install deps
with `pnpm install`; run scripts with `pnpm run <script>` or `pnpm <script>`.

### Build

The library is built with `tsc` (not `vite build`). `vite.config.ts` exists only
to configure Vitest and to run `vite dev` as a server for Playwright. Running
`pnpm run build` compiles `src/` to `dist/` via `tsconfig.json`.

### Two tsconfigs

- `tsconfig.json` — library build only; includes `src/**/*`
- `tsconfig.dev.json` — extends the above with `noEmit: true`; adds `test/**/*`, `vite.config.ts`, and
  `playwright.config.ts` so ESLint's type-aware rules cover all files

Do not add test files to `tsconfig.json` — they would be emitted into `dist/`.

### Tests

- `test/node/` — Vitest unit tests (`pnpm run test-node`); run in Node
- `test/browser/` — Playwright tests (`pnpm run test-browser`); run in real
  Chromium via a Vite dev server (`pnpm run dev`)

The `dev` script exists solely to give Playwright a server that can serve and
transform TypeScript source files on the fly. There is no browser app.

### ESM & import paths

The package is ESM-only (`"type": "module"`). Local imports must use the `.js`
extension even though source files are `.ts` — e.g.
`import { Example } from '../../src/index.js'`. TypeScript's `moduleResolution: Bundler`
resolves these to the `.ts` source at compile time.

## Library Architecture

This library has a single export, `verifyCapabilityInvocation` (`src/index.ts`),
which verifies a zcap invocation carried in HTTP signature headers. A few
non-obvious points:

### Two base64 codecs (`src/baseX.ts`)

There are two distinct, non-interchangeable decodes; `src/baseX.ts` names both:

- `base64decode` (`@scure/base` `base64`, **padded** standard alphabet) decodes
  the `signature="..."` value from the `Authorization` header. The signer emits
  it padded (`Buffer.toString('base64')` / `btoa` / `toBase64()`).
- `base64url` (`@scure/base` `base64urlnopad`, **unpadded** url-safe) decodes
  the gzipped capability from the `capability-invocation` header. The signer
  emits it unpadded (`Buffer.toString('base64url')` / `omitPadding: true`).

Do not swap them: `base64urlnopad` rejects the `=` padding the signature
carries, and `base64` rejects the url-safe `-_` alphabet.

### The HTTP signature is verified directly, not via jsonld-signatures

`verifyCapabilityInvocation` calls `verifier.verify({ data, signature })`
itself. `purpose.validate()` (zcap `CapabilityInvocation`) only runs the
proof-purpose and delegation-chain checks against the `verificationMethod` that
`getVerifier` returns. Consequences:

- **Key revocation is enforced by `getVerifier`**, not by the library. The
  reference `getVerifier` dereferences the key doc and calls
  `Ed25519VerificationKey.fromKeyDocument({ document })`, which throws if the
  doc carries `revoked` (the `crypto-ld` `fromKeyId` replacement). jsigs'
  `LinkedDataSignature` revocation check is never reached for the invocation
  signature.
- The verify-mode delegation `suite` needs no signer:
  `new Ed25519Signature2020()` is sufficient.

### Controller documents should use the DID v1 context

jsonld-signatures' `ControllerProofPurpose` frames the controller document
against the legacy `security/v2` context **unless** the controller doc's
`@context` is the DID v1 context (`https://www.w3.org/ns/did/v1`) and the proof
term (`capabilityInvocation`) is a DID verification relationship. Real DID
controllers skip the frame. A controller doc with a non-DID context forces a
`security/v2` fetch, which `@interop/security-document-loader` does not bundle,
so verification fails. The test fixtures use real `did:key` controllers, which
`@interop/security-document-loader` resolves to a DID v1 + Multikey document via
its built-in did:key resolver, so they skip the frame automatically. (Only the
root capability is registered as a static document, since the zcap proof purpose
dereferences `urn:zcap:root:...` ids through the loader, which has no handler
that reconstructs root zcaps from their id.)

### Keys are `Multikey` documents

`@interop/ed25519-verification-key`'s `.export()` emits a `Multikey` document
(`type: 'Multikey'`, `publicKeyMultibase`, `multikey/v1` context), not the
legacy `Ed25519VerificationKey2020` shape. This verifies end-to-end through
`@interop/zcap` + `@interop/ed25519-signature`. `fromKeyDocument()` accepts
either the Multikey or the ed25519-2020 suite context (fixed upstream in
`@interop/ed25519-verification-key@7.0.1`).

### Browser test fixtures

Playwright specs (`test/browser/*.spec.ts`) cannot import the heavy isomorphic
deps directly in `page.evaluate`. Instead, the test logic lives in a fixture
module (e.g. `test/browser/verify-fixture.ts`) that the spec imports in-page
via a variable-held, extension-qualified rooted path with `@vite-ignore`:

```ts
const fixturePath = '/test/browser/verify-fixture.ts'
await page.evaluate(async path => {
  const { runHappyPath } = await import(/* @vite-ignore */ path)
  return runHappyPath()
}, fixturePath)
```

The variable indirection stops TypeScript from trying to resolve the rooted
`/test/...` path at compile time (ambient `declare module` does not apply to
rooted paths); Vite serves and transforms the fixture at runtime.

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.
