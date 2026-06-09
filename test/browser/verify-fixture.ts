/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin. All rights reserved.
 */
import { createRootCapability } from '@interop/zcap'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { securityLoader } from '@interop/security-document-loader'
import type { IKeyPairCore, IVerificationMethod } from '@interop/data-integrity-core'
import type { IDocumentLoader } from '@interop/data-integrity-core/loader'
import { verifyCapabilityInvocation } from '../../src/index.js'

const invocationResourceUrl = 'https://test.org/zcaps/foo'
const method = 'GET'

/**
 * Runs a full happy-path capability-invocation verification entirely in the
 * browser. The `did:key` controller and its verification method resolve through
 * `@interop/security-document-loader`'s built-in did:key resolver; only the
 * root capability is registered as a static document.
 *
 * @returns {Promise<boolean>} Whether the invocation verified.
 */
export async function runHappyPath(): Promise<boolean> {
  // Use a real `did:key` controller so the loader resolves the controller DID
  // document and the verification method automatically (for Ed25519, both the
  // did:key id and the key id fragment are the key's multibase fingerprint).
  const keyPair = await Ed25519VerificationKey.generate()
  const controller = `did:key:${keyPair.fingerprint()}`
  const keyId = `${controller}#${keyPair.fingerprint()}`
  keyPair.controller = controller
  keyPair.id = keyId
  const suite = new Ed25519Signature2020()

  const rootCapability = createRootCapability({
    controller,
    invocationTarget: invocationResourceUrl
  })

  // The loader already bundles the security/zcap/key contexts and resolves
  // `did:key` controllers and keys; only the root capability must be registered,
  // since the zcap proof purpose dereferences `urn:zcap:root:...` ids through it.
  const loaderBuilder = securityLoader()
  loaderBuilder.addStatic(rootCapability.id, rootCapability)
  const documentLoader = loaderBuilder.build()

  const getVerifier = async ({
    keyId,
    documentLoader
  }: {
    keyId: string
    documentLoader: IDocumentLoader
  }) => {
    const { document } = await documentLoader(keyId)
    const key = await Ed25519VerificationKey.fromKeyDocument({
      document: document as IKeyPairCore
    })
    return {
      verifier: key.verifier(),
      verificationMethod: document as IVerificationMethod
    }
  }

  const invocationSigner = keyPair.signer()
  invocationSigner.id = keyId
  const signed = await signCapabilityInvocation({
    url: invocationResourceUrl,
    method,
    headers: { keyId },
    json: { foo: true },
    invocationSigner,
    capabilityAction: 'read'
  })
  // browsers strip the host header; set it explicitly for verification
  signed.host = signed.host || 'test.org'

  const result = await verifyCapabilityInvocation({
    url: invocationResourceUrl,
    method,
    suite,
    headers: signed as Record<string, string>,
    expectedHost: 'test.org',
    expectedAction: 'read',
    expectedRootCapability: rootCapability.id,
    getVerifier,
    documentLoader,
    expectedTarget: invocationResourceUrl
  })

  return result.verified
}

/**
 * Exercises the real `@interop/security-document-loader` in the browser by
 * resolving a context it bundles statically. Confirms the loader not only
 * bundles and initializes under Vite, but actually returns documents at
 * runtime.
 *
 * @returns {Promise<boolean>} Whether a bundled context resolved to a document.
 */
export async function loaderResolvesBundledContext(): Promise<boolean> {
  const documentLoader = securityLoader().build()
  const { document } = await documentLoader(
    'https://w3id.org/security/multikey/v1'
  )
  return document != null
}
