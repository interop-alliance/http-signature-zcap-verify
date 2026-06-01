# Conversion Plan: `@interop/http-signature-zcap-verify`

Convert this repo from a Digital Bazaar JavaScript library (mocha/karma, npm,
`eslint-config-digitalbazaar`) to a TypeScript isomorphic library matching the
`/home/dmitri/code/Interop/isomorphic-lib-template` toolchain (pnpm, tsc,
Vitest, Playwright, prettier + flat eslint), and swap the `@digitalbazaar/*`
dependencies for their `@interop/*` forks.

The project `CLAUDE.md` is already written for the **post-conversion** state
(it documents pnpm, `src/`, `tsconfig.json`/`tsconfig.dev.json`, Vitest +
Playwright, the `.js`-extension ESM import rule). This plan implements exactly
that target.

---

## 1. Current state (snapshot)

- **Source:** `lib/index.js` (single export `verifyCapabilityInvocation`),
  `lib/util.js` + `lib/util-browser.js` (a `base64Decode` node/browser split,
  wired via the `package.json` `"browser"` field).
- **Tests:** `tests/10-verify.spec.js` (mocha + chai `should`),
  `tests/document-loader.js`, `tests/test-mocha.js` (chai + `isomorphic-webcrypto`
  polyfill), `tests/test-karma.js`.
- **Tooling:** npm + `package-lock.json`, mocha, karma + webpack, c8,
  `eslint-config-digitalbazaar`, `.eslintrc.cjs`, `karma.conf.cjs`,
  `.github/workflows/main.yml`.
- **Runtime deps:** `@digitalbazaar/http-signature-header`,
  `@digitalbazaar/zcap`, `base64url-universal`, `pako`.

## 2. Target state

- **Source:** `src/index.ts`, `src/baseX.ts` (base helpers via `@scure/base`).
  No node/browser split file -- `@scure/base` is isomorphic, so the
  `package.json` `"browser"` field is dropped.
- **Build:** `tsc` emits `src/` to `dist/`. `exports`/`module`/`browser`/`types`
  point at `dist`.
- **Tests:** `test/node/*.test.ts` (Vitest), `test/browser/*.spec.ts` +
  `test/index.html` (Playwright via `vite dev`).
- **Tooling:** pnpm, Vitest (+ v8 coverage), Playwright, prettier, flat
  `eslint.config.js` (`typescript-eslint` + `eslint-config-prettier`), template
  `tsconfig.json` / `tsconfig.dev.json` / `vite.config.ts` /
  `playwright.config.ts`, template `.github/workflows/ci.yml` + `publish.yml`.

---

## 3. Dependency changes

### Runtime `dependencies`

| Action | From | To |
| --- | --- | --- |
| swap | `@digitalbazaar/http-signature-header` ^5 | `@interop/http-signature-header` ^5.0.2 |
| swap | `@digitalbazaar/zcap` ^9 | `@interop/zcap` ^10.1.0 |
| swap | `base64url-universal` ^2 | `@scure/base` (same range as `ed25519-verification-key`) |
| keep | `pako` ^2 | `pako` ^2 |

> `@interop/zcap` is **v10** (was v9). Re-verify `CapabilityInvocation`,
> `createRootCapability`, and `constants` (all still exported from `lib/index.js`
> in the fork -- confirmed) behave the same; note the major bump as a risk
> (Section 7).

### `devDependencies`

Remove (Digital Bazaar test stack + tooling no longer used):
`@digitalbazaar/security-context`, `aes-key-wrapping-2019-context`,
`sha256-hmac-key-2019-context`, `zcap-context`, `crypto-ld`,
`isomorphic-webcrypto`, `c8`, `chai`, `cross-env`,
`eslint-config-digitalbazaar`, `eslint-plugin-jsdoc`, `eslint-plugin-unicorn`,
`mocha`, `mocha-lcov-reporter`, all `karma*`, `webpack`.

Swap:

| From | To |
| --- | --- |
| `@digitalbazaar/security-document-loader` ^2 | `@interop/security-document-loader` ^9.1.0 |
| `@digitalbazaar/http-signature-zcap-invoke` ^6 | `@interop/http-signature-zcap-invoke` ^6.2.0 |
| `@digitalbazaar/ed25519-signature-2020` ^5 | `@interop/ed25519-signature` ^7.0.0 (see note) |
| `@digitalbazaar/ed25519-verification-key-2020` ^4 | `@interop/ed25519-verification-key` ^7.0.0 |

Add (from template): `@eslint/js`, `@playwright/test`, `@types/node`,
`@vitest/coverage-v8`, `eslint`, `eslint-config-prettier`, `globals`,
`prettier`, `rimraf`, `typescript`, `typescript-eslint`, `vite`, `vitest`.

> The `aes-*`, `sha256-hmac-*`, `zcap-context`, and `security-context` contexts
> are **bundled inside** `@interop/security-document-loader` (verified: its
> `documentLoader.ts` imports and `addStatic`s zcap, aes, hmac, ed25519, did
> contexts and ships the did:key driver + `Ed25519VerificationKey`). This is why
> they can be removed, and why `crypto-ld` is no longer needed for keyId
> dereferencing.

### Fork resolution

Consume the `@interop/*` forks from the **npm registry** (their published
versions, as pinned in the tables above), not via pnpm `workspace:`/`link:`/
`file:` references. The local checkouts under `/home/dmitri/code/Interop/` are
only for reading source/API while porting.

---

## 4. Source port (`lib/` to `src/`)

### 4a. `src/baseX.ts` (replaces `lib/util.js` + `lib/util-browser.js`)

Model on `/home/dmitri/code/Interop/ed25519-verification-key/src/baseX.ts`:

```ts
import { base64, base64urlnopad } from '@scure/base'

export const base64decode = base64        // RFC 4648, standard alphabet, PADDED
export const base64url = base64urlnopad    // RFC 4648 url-safe, UNPADDED
```

There are **two distinct base64 decodes** in `index.js` today; they use
different alphabets *and* different padding, so do not conflate them. Both
variants are confirmed against the encoder in `@interop/http-signature-zcap-invoke`
(`lib/util.js` + `lib/util-browser.js`):

1. **Signature** -- `base64Decode(b64Signature)` decodes the `signature="..."`
   value from the `Authorization` header. The signer encodes it with
   `Buffer…toString('base64')` (Node) and `bytes.toBase64()` / `btoa(...)`
   (browser) -- i.e. **standard alphabet, padded**. Decode with `@scure/base`'s
   **`base64`** (padded). NB: `atob`/`btoa` are the *padded* variant, so this is
   **not** `base64nopad` -- `base64nopad` would reject the trailing `=`.
2. **Capability** -- `base64url.decode(capability)` decodes the gzipped
   capability from the `capability-invocation` header. The signer encodes it
   with `Buffer…toString('base64url')` (Node) and
   `toBase64({ alphabet: 'base64url', omitPadding: true })` / a
   `.replaceAll('=', '')` fallback (browser) -- i.e. **url-safe alphabet,
   unpadded**. Decode with `@scure/base`'s **`base64urlnopad`**.

> `@scure/base` is strict (the padded `base64` requires correct `=` padding;
> `base64urlnopad` requires none). Both match the encoder above exactly, so no
> stripping/normalization is needed. If a round-trip ever fails in tests,
> re-check which alphabet/padding the producing side used rather than loosening
> the decoder.

This removes the node/browser split entirely, so also drop the
`package.json` `"browser": { "./lib/util.js": "./lib/util-browser.js" }` map.

### 4b. `src/index.ts` (port of `lib/index.js`)

- Convert `verifyCapabilityInvocation` to TypeScript. Define an
  `interface VerifyCapabilityInvocationOptions` for the large options object
  and a result interface (`{ verified: boolean; error?: Error; ... }`),
  following the per-property JSDoc/`@param options.x` style mandated by
  `CLAUDE.md`. Reuse the existing JSDoc text.
- Update imports:
  - `import { CapabilityInvocation, constants } from '@interop/zcap'`
  - `import { parseRequest, parseSignatureHeader } from '@interop/http-signature-header'`
  - `import { base64decode, base64url } from './baseX.js'`  (`.js` extension, per CLAUDE.md ESM rule)
  - `import pako from 'pako'`
- Replace `base64Decode(b64Signature)` to `base64decode.decode(b64Signature)`
  and `base64url.decode(capability)` to `base64url.decode(capability)`.
- Preserve existing comments and the side-channel note verbatim
  (`CLAUDE.md`: "Preserve existing comments and formatting").
- Keep `_lowerCaseObjectKeys` as a module-level helper; under prettier's
  `semi: false` the file will be reformatted -- run `pnpm run fix` to normalize.
- Type friction to expect: `error.name = '...'`, `error.host = ...` custom
  properties on `Error`. Either cast (`const error = new Error(...) as Error & {...}`)
  or define a small `interface VerificationError extends Error`. `@scure/base`
  `.decode` returns `Uint8Array` (good -- `verifier.verify` and `pako.ungzip`
  both accept it).
- `src/index.ts` re-exports nothing else; the package's single public entry is
  `verifyCapabilityInvocation`.

---

## 5. Test rewrite (`tests/` to `test/`)

This is the highest-effort part because the key/suite APIs changed shape.

### 5a. `test/node/10-verify.test.ts` (port of `tests/10-verify.spec.js`)

- Framework: `import { describe, it, expect, beforeEach } from 'vitest'`.
  Convert every chai `should.*` assertion to `expect`:
  - `should.exist(x)` to `expect(x).toBeDefined()`
  - `result.verified.should.equal(true)` to `expect(result.verified).toBe(true)`
  - `error.message.should.contain('x')` to `expect(error.message).toContain('x')`
  - `params.should.include.keys([...])` to per-key `expect(params).toHaveProperty(...)`.
- Remove the chai `should` global and the `isomorphic-webcrypto` polyfill
  (`tests/test-mocha.js` is deleted; Vitest needs no global setup, and the
  `@noble` ed25519 implementation in the interop key needs no WebCrypto shim).

**Key generation / suite construction changed:**

Old (`crypto-ld` + DB suites):
```js
const cryptoLd = new CryptoLD(); cryptoLd.use(Ed25519VerificationKey2020)
keyPair = await cryptoLd.generate({ controller, type })
const suite = new Suite({ verificationMethod: keyId, key: keyPair })
```

New (`@interop/*`):
```ts
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
// generate
const keyPair = await Ed25519VerificationKey.generate({ controller })
const keyId = keyPair.id
const invocationSigner = keyPair.signer()  // has .sign({data}); set .id = keyId
// suite (interop ctor is { signer, date }, NOT { verificationMethod, key })
const suite = new Ed25519Signature2020({ signer: invocationSigner })
```

> **API shape changes to handle (verify against the fork source):**
> - `@interop/ed25519-verification-key` exports `Ed25519VerificationKey` (not
>   `...2020`); `.export()` emits a **`Multikey`** document with
>   `publicKeyMultibase` (not the `Ed25519VerificationKey2020` shape). The test's
>   verification-method `type` assertions and the document-loader docs must use
>   the Multikey shape.
> - `@interop/ed25519-signature`'s `Ed25519Signature2020` extends
>   `DataIntegrityProof` and takes `{ signer, date }`. Confirm it still
>   interoperates with `@interop/zcap`'s `CapabilityInvocation.validate` for
>   delegation-chain verification (this is the `suite` argument passed into
>   `verifyCapabilityInvocation`).

**`getVerifier` / `cryptoLd.fromKeyId` replacement.** The old test did
`cryptoLd.fromKeyId({ id, documentLoader })`. The interop equivalent is the
`Ed25519VerificationKey.fromFingerprint()` static method -- no hand-written key
reconstruction needed. The helper:
1. dereferences `keyId` via `documentLoader` to get the verification-method doc
   (this preserves the `revoked` field that the "should THROW if
   verificationMethod has been revoked" test depends on),
2. rebuilds the public key via
   `Ed25519VerificationKey.fromFingerprint({ fingerprint: doc.publicKeyMultibase })`,
   and
3. returns `{ verifier: key.verifier(), verificationMethod: doc }`.

```ts
const getVerifier = async ({ keyId, documentLoader }) => {
  const { document } = await documentLoader(keyId)
  const key = Ed25519VerificationKey.fromFingerprint({
    fingerprint: document.publicKeyMultibase
  })
  return { verifier: key.verifier(), verificationMethod: document }
}
```

Confirm `key.verifier()` returns an `IVerifier` exposing
`.verify({ data, signature })` (the shape `index.ts` calls). Adjust if the
interop verifier uses a different method name.

**`signCapabilityInvocation`** comes from `@interop/http-signature-zcap-invoke`
(same call signature expected). **`createRootCapability`** from `@interop/zcap`.

### 5b. `test/node/document-loader.ts` (port of `tests/document-loader.js`)

Collapse to the interop loader, which already bundles zcap/aes/hmac/security/
ed25519/did contexts:
```ts
import { securityLoader } from '@interop/security-document-loader'
export const securityDocumentLoader = securityLoader().build()
```
Drop all the manual `addStatic` calls and the removed context imports. If a
specific context the tests rely on is *not* bundled, add it back with a single
`addStatic` (verify during the test pass).

### 5c. `test/browser/10-verify.spec.ts` + `test/index.html`

- Add `test/index.html` (copy template's empty-body dev page).
- Add a Playwright spec mirroring `test/browser/Example.spec.ts`: navigate to
  `/test/index.html`, `page.evaluate` a dynamic `import('/src/index.ts')`, run a
  minimal happy-path `verifyCapabilityInvocation` (or at least an import +
  smoke check) in real Chromium. Full crypto setup in-browser may be heavy;
  a smoke test that the module loads and a valid request verifies is sufficient
  for the "isomorphic" guarantee.

### 5d. Delete

`tests/test-mocha.js`, `tests/test-karma.js`, `tests/.eslintrc.cjs`, and the
whole `tests/` dir once ported to `test/`.

---

## 6. Config & tooling files

**Copy from the template (verbatim, then adjust):**
- `tsconfig.json`, `tsconfig.dev.json` -- the dev config already includes
  `test/**/*.ts`, `vite.config.ts`, `playwright.config.ts`. Do **not** add tests
  to `tsconfig.json` (CLAUDE.md: they'd be emitted to `dist/`).
- `vite.config.ts` -- keep; its `include` already covers `test/node/**/*.test.ts`.
- `playwright.config.ts` -- keep.
- `eslint.config.js`, `prettier.config.js` (`semi: false, singleQuote: true`),
  `.editorconfig`.
- `.gitignore` -- replace with template's (ignores `dist`, `coverage`,
  `playwright-report/`, `test-results/`, `package-lock.json`).
- `.github/workflows/ci.yml` + `publish.yml` -- replace `main.yml`. CI runs
  lint, build, `test-node`, then Playwright (`pnpm exec playwright install`).

**Rewrite `package.json`:**
- `name`: `@interop/http-signature-zcap-verify`; `author`/`repository`/`bugs`/
  `homepage` to Interop Alliance; `license` **stays BSD-3-Clause** (unchanged).
- Replace `exports`/add `module`/`browser`/`types` to point at `dist`
  (template shape: `exports["."]` with `types`/`react-native`/`import`).
  Remove the `"browser"` util override and `files: ["lib/**/*.js"]` to
  `files: ["dist", "README.md", "LICENSE.md"]`.
- Scripts to template set: `build` (`pnpm run clear && tsc`), `clear`, `dev`,
  `fix`, `format`, `lint`, `prepare`, `rebuild`, `test`
  (`lint && test-node && test-browser`), `test-browser`, `test-node`,
  `test-coverage`. Drop all mocha/karma/c8 scripts and the `c8` block.
- `"type": "module"` stays. `engines.node` to `>=24.0` (match the template;
  current is `>=18`). Add `packageManager: "pnpm@..."`, `sideEffects: false`,
  `publishConfig`.

**Delete:** `.eslintrc.cjs`, `karma.conf.cjs`, `package-lock.json`, `lib/`,
`node_modules/` (reinstall with pnpm).

**`CHANGELOG.md`:** add a new top entry (per global instructions, version stays
unmanaged; use **TBD** as the date) summarizing: TypeScript rewrite, toolchain
migration, and the `@digitalbazaar/*` to `@interop/*` dependency swaps. Do not
bump `version` in `package.json`.

**`README.md`:** update install (`pnpm add`), package name, import examples, and
the `@interop/*` references.

---

## 7. Resolved decisions

- **Fork resolution:** use **published npm versions** of the `@interop/*`
  forks (Section 3, "Fork resolution"); no workspace/link references.
- **License:** **stays BSD-3-Clause** (unchanged).
- **Engines:** bump to `>=24.0` to match the template.
- **`@interop/zcap` v10:** accepted as fine; not treated as a risk.

## 8. Open questions / risks (verify while executing)

1. **The core curiosity -- does verification pass with `Multikey`?**
   `@interop/ed25519-verification-key` produces a `Multikey` verification-method
   doc (`publicKeyMultibase`) rather than the legacy `Ed25519VerificationKey2020`
   shape. Expectation: it *should* work end-to-end through `@interop/zcap` +
   `@interop/ed25519-signature`. This conversion is partly a way to find out.
   Update the test's type-related assertions accordingly (e.g. the
   `"AESVerificationKey2001" is not installed` case may surface a different
   message in the new stack).
2. **`Ed25519Signature2020` interop.** The interop suite is `DataIntegrityProof`-
   based, not jsigs-based. Confirm the delegation-chain `suite` argument still
   verifies invocation proofs created by `@interop/http-signature-zcap-invoke`.
3. **`getVerifier`/verifier method name** -- confirm `key.verifier()` exposes
   `.verify({ data, signature })` (Section 5a).
4. **Is `@interop/ed25519-signature` still needed?** The task says "if it's
   still needed." It is used in the test only to build the delegation-chain
   `suite`. If a happy-path verify can be exercised without constructing a
   delegation suite, the dep may be droppable -- decide during the test pass.

---

## 9. Suggested execution order

1. `git switch -c ts-conversion` (work on a branch).
2. Scaffold configs: copy template `tsconfig*.json`, `vite.config.ts`,
   `playwright.config.ts`, `eslint.config.js`, `prettier.config.js`,
   `.editorconfig`, `.gitignore`, `.github/workflows/*`.
3. Rewrite `package.json` (deps, scripts, exports, metadata). `pnpm install`
   (published `@interop/*` versions from npm).
4. Port source: `src/baseX.ts`, then `src/index.ts`. `pnpm run build` until
   `tsc` is clean.
5. Port tests: `test/node/document-loader.ts`, `test/node/10-verify.test.ts`.
   `pnpm run test-node` -- iterate on the API-shape risks (Section 8).
6. Add `test/index.html` + `test/browser/10-verify.spec.ts`.
   `pnpm exec playwright install chromium && pnpm run test-browser`.
7. `pnpm run lint` / `pnpm run fix`. Update `README.md`, `CHANGELOG.md`.
8. Delete `lib/`, `tests/`, `.eslintrc.cjs`, `karma.conf.cjs`,
   `package-lock.json`, old `main.yml`.
9. Final `pnpm test` (lint + node + browser) green.

> Per global instructions: do **not** commit, open a PR, or bump the
> `package.json` version -- leave those to the maintainer.
