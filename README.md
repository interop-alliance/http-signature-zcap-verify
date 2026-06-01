# http-signature-zcap-verify _(@interop/http-signature-zcap-verify)_

A library for verifying Authorization Capability (ZCAP) invocations via HTTP
signatures.

It is the verifier counterpart to
[`@interop/http-signature-zcap-invoke`](https://github.com/interop-alliance/http-signature-zcap-invoke),
which signs the request. On the server, `verifyCapabilityInvocation` parses the
HTTP signature headers, verifies the signature, dereferences the invoked
capability, and validates the capability delegation chain.

## Install

- Browsers, Node.js, and React Native are supported.
- Written in TypeScript; ships ESM with type declarations.

To install from NPM:

```
pnpm add @interop/http-signature-zcap-verify
```

## Usage

`verifyCapabilityInvocation` needs two functions you supply:

- **`documentLoader`** -- a JSON-LD document loader that can resolve the
  controller document, the invoked root capability, and any contexts in the
  delegation chain.
- **`getVerifier`** -- an async function that dereferences a key id to a
  signature verifier and its verification method document.

### Setting up the document loader and verifier

```ts
import { securityLoader } from '@interop/security-document-loader'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

// Preloaded with the zcap, DID, Multikey, ed25519, and data-integrity contexts.
const documentLoader = securityLoader().build()

async function getVerifier({ keyId, documentLoader }) {
  const { document } = await documentLoader(keyId)
  // `fromKeyDocument` rebuilds the key from the dereferenced verification
  // method and throws if the key has been revoked. It accepts a verification
  // method using either the Multikey or the ed25519-2020 suite context.
  const key = await Ed25519VerificationKey.fromKeyDocument({ document })
  return { verifier: key.verifier(), verificationMethod: document }
}
```

> **Note:** the controller document returned by your `documentLoader` should use
> the DID v1 context (`https://www.w3.org/ns/did/v1`) and list the invoking key
> under `capabilityInvocation`. Controllers that use a non-DID context force a
> framing step against the legacy `https://w3id.org/security/v2` context, which
> the loader above does not bundle.

### Verifying an incoming request

```ts
import { verifyCapabilityInvocation } from '@interop/http-signature-zcap-verify'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'

// In an HTTP handler, `req.method`, `req.url`, and `req.headers` come from the
// incoming request. `expectedTarget` is the absolute URL the capability must
// apply to; `expectedRootCapability` is the root zcap ID you authorized.
const result = await verifyCapabilityInvocation({
  url: req.url,
  method: req.method,
  headers: req.headers,
  // verify-mode suite for the delegation chain; no signer needed
  suite: new Ed25519Signature2020(),
  getVerifier,
  documentLoader,
  expectedHost: 'api.example.com',
  expectedAction: 'read',
  expectedTarget: 'https://api.example.com/documents/123',
  expectedRootCapability:
    'urn:zcap:root:' +
    encodeURIComponent('https://api.example.com/documents/123')
})

if (!result.verified) {
  // `result.error` describes why verification failed (bad signature,
  // unexpected host, expired capability, unauthorized key, etc.)
  throw result.error
}

// On success, `result` also includes the invoked `capability`,
// `capabilityAction`, the `controller`/`invoker`, the `verificationMethod`,
// and the `dereferencedChain`.
console.log('invoked by', result.controller)
```

### Result

`verifyCapabilityInvocation` resolves to an object and does not throw for
verification failures -- check `result.verified`:

- On failure: `{ verified: false, error }`.
- On success: `{ verified: true, capability, capabilityAction, controller,
invoker, verificationMethod, dereferencedChain }`.

(It does throw a `TypeError` for programmer errors, such as omitting
`getVerifier`.)

### Key options

| Option                     | Description                                                               |
| -------------------------- | ------------------------------------------------------------------------- |
| `url`, `method`, `headers` | The incoming request.                                                     |
| `getVerifier`              | Async function returning `{ verifier, verificationMethod }` for a key id. |
| `documentLoader`           | JSON-LD loader for the controller, root capability, and contexts.         |
| `expectedHost`             | The expected `Host` header (string or array of allowed hosts).            |
| `expectedAction`           | The capability action the request must invoke (e.g. `'read'`).            |
| `expectedTarget`           | The absolute URL the capability must apply to.                            |
| `expectedRootCapability`   | The authorized root capability ID (string or array).                      |
| `suite`                    | The signature suite(s) used to verify the delegation chain.               |
| `allowTargetAttenuation`   | Allow hierarchical RESTful target attenuation (default `false`).          |
| `maxClockSkew`             | Allowed clock skew in seconds (default `300`).                            |
| `now`                      | A UNIX timestamp (seconds) or `Date` to verify against (default: now).    |

See the JSDoc on `verifyCapabilityInvocation` for the full list, including
`additionalHeaders`, `beforeValidatePurpose`, `inspectCapabilityChain`,
`maxChainLength`, and `maxDelegationTtl`.
