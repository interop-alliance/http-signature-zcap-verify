/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin. All rights reserved.
 */
import { createRootCapability } from '@interop/zcap'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { securityDocumentLoader } from '../node/document-loader.js'
import { verifyCapabilityInvocation, type DocumentLoader } from '../../src/index.js'

const controller = 'did:test:controller'
const invocationResourceUrl = 'https://test.org/zcaps/foo'
const method = 'GET'
const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1'

/**
 * Runs a full happy-path capability-invocation verification entirely in the
 * browser. The document loader is self-contained (it serves the mock
 * controller, key, and root capability documents); the verification path does
 * not require any additional remote contexts.
 *
 * @returns {Promise<boolean>} Whether the invocation verified.
 */
export async function runHappyPath(): Promise<boolean> {
  const keyPair = await Ed25519VerificationKey.generate({ controller })
  const keyId = keyPair.id as string
  const suite = new Ed25519Signature2020()

  const rootCapability = createRootCapability({
    controller,
    invocationTarget: invocationResourceUrl
  })

  const documentLoader: DocumentLoader = async uri => {
    if (uri === controller) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: {
          id: controller,
          '@context': DID_CONTEXT_URL,
          capabilityInvocation: [keyId]
        }
      }
    }
    if (uri === keyId) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: keyPair.export({ publicKey: true, includeContext: true })
      }
    }
    if (uri === rootCapability.id) {
      return { contextUrl: null, documentUrl: uri, document: rootCapability }
    }
    return securityDocumentLoader(uri)
  }

  const getVerifier = async ({
    keyId,
    documentLoader
  }: {
    keyId: string
    documentLoader: DocumentLoader
  }) => {
    const { document } = (await documentLoader(keyId)) as {
      document: Record<string, unknown>
    }
    const key = await Ed25519VerificationKey.fromKeyDocument({ document })
    return { verifier: key.verifier(), verificationMethod: document }
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
  const { document } = await securityDocumentLoader(
    'https://w3id.org/security/multikey/v1'
  )
  return document != null
}
