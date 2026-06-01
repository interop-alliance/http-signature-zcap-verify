/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc. and Interop Alliance. All rights reserved.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { createRootCapability, constants } from '@interop/zcap'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { securityDocumentLoader } from './document-loader.js'
import type { IVerificationMethod } from '@interop/data-integrity-core'
import type { IDocumentLoader } from '@interop/data-integrity-core/loader'
import {
  verifyCapabilityInvocation,
  type GetVerifier
} from '../../src/index.js'

const { ZCAP_CONTEXT_URL } = constants

// The mock controller is a DID, so its document uses the DID v1 context. This
// context defines the `capabilityInvocation` verification relationship, which
// lets jsonld-signatures authorize the verification method without framing the
// controller document against the legacy `security/v2` context.
const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1'

const controller = 'did:test:controller'

const invocationResourceUrl = 'https://test.org/zcaps/foo'
const method = 'GET'

let keyPair: Ed25519VerificationKey

async function setup() {
  const expectedHost = 'test.org'
  // the tests will use a mock didKey.
  keyPair = await Ed25519VerificationKey.generate({ controller })
  const keyId = keyPair.id as string
  // verify-mode suite; no signer needed to verify the delegation chain.
  const suite = new Ed25519Signature2020()

  // this is the root zCap
  const rootCapability = createRootCapability({
    controller,
    invocationTarget: invocationResourceUrl
  })

  const documentLoader: IDocumentLoader = async uri => {
    // the controller should return a didDocument
    // with the ProofPurpose's term on it
    // In this case that term is capabilityInvocation
    if (uri === controller) {
      const doc = {
        id: controller,
        '@context': DID_CONTEXT_URL,
        capabilityInvocation: [keyId]
      }
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      }
    }
    // when we dereference the keyId for verification
    // all we need is the publicNode
    if (uri === keyId) {
      const doc = keyPair.export({ publicKey: true, includeContext: true })
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      }
    }
    if (uri === rootCapability.id) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      }
    }
    return securityDocumentLoader(uri)
  }
  const getVerifier: GetVerifier = async ({ keyId, documentLoader }) => {
    const { document } = (await documentLoader(keyId)) as {
      document: Record<string, unknown>
    }
    // `fromKeyDocument` builds the key from the dereferenced verification
    // method and throws if it has been revoked (the crypto-ld `fromKeyId`
    // equivalent). It accepts either the ed25519-2020 suite context or the
    // Multikey context emitted by `export()`.
    const key = await Ed25519VerificationKey.fromKeyDocument({ document })
    return {
      verifier: key.verifier(),
      verificationMethod: document as unknown as IVerificationMethod
    }
  }
  // we need a signer just for the sign step
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
  // in browsers we need to set the host explicitly
  signed.host = signed.host || expectedHost
  return {
    expectedHost,
    // method used in tests is always GET which maps to `read`
    expectedAction: 'read',
    expectedRootCapability: rootCapability.id,
    keyId,
    keyPair,
    suite,
    signed: signed as Record<string, string>,
    documentLoader,
    getVerifier
  }
}

describe('verifyCapabilityInvocation', () => {
  describe('Ed25519VerificationKey2020', () => {
    let suite: Ed25519Signature2020
    let documentLoader: IDocumentLoader
    let keyId: string
    let getVerifier: GetVerifier
    let signed: Record<string, string>
    let expectedHost: string
    let expectedAction: string
    let expectedRootCapability: string

    beforeEach(async () => {
      ;({
        expectedHost,
        expectedAction,
        expectedRootCapability,
        suite,
        documentLoader,
        keyId,
        getVerifier,
        signed
      } = await setup())
    })

    it('should verify a valid request', async () => {
      const result = await verifyCapabilityInvocation({
        url: invocationResourceUrl,
        method,
        suite,
        headers: signed,
        expectedHost,
        expectedAction,
        expectedRootCapability,
        getVerifier,
        documentLoader,
        expectedTarget: invocationResourceUrl
      })
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result.verified).toBeTypeOf('boolean')
      expect(result.verified).toBe(true)
    })

    it('should call `beforeValidatePurpose` handler', async () => {
      let called = 0
      let params: Record<string, unknown> | undefined
      const result = await verifyCapabilityInvocation({
        url: invocationResourceUrl,
        method,
        suite,
        headers: signed,
        expectedHost,
        expectedAction,
        expectedRootCapability,
        getVerifier,
        documentLoader,
        expectedTarget: invocationResourceUrl,
        beforeValidatePurpose(_params) {
          called += 1
          params = _params
        }
      })
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result.verified).toBeTypeOf('boolean')
      expect(result.verified).toBe(true)
      expect(called).toBe(1)
      expect(Object.keys(params ?? {})).toEqual(
        expect.arrayContaining([
          'capability',
          'capabilityAction',
          'purpose',
          'proof'
        ])
      )
    })

    it('should verify a valid request when "now" is a JS date instance', async () => {
      const now = new Date(Date.now())
      const result = await verifyCapabilityInvocation({
        url: invocationResourceUrl,
        method,
        suite,
        headers: signed,
        expectedHost,
        expectedAction,
        expectedRootCapability,
        expectedTarget: invocationResourceUrl,
        getVerifier,
        documentLoader,
        now
      })
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result.verified).toBeTypeOf('boolean')
      expect(result.verified).toBe(true)
    })

    it('should verify a valid request with multiple expectedHosts', async () => {
      const result = await verifyCapabilityInvocation({
        url: invocationResourceUrl,
        method,
        suite,
        headers: signed,
        expectedHost: [expectedHost, 'bar.org'],
        expectedAction,
        expectedRootCapability,
        expectedTarget: invocationResourceUrl,
        getVerifier,
        documentLoader
      })
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result.verified).toBeTypeOf('boolean')
      expect(result.verified).toBe(true)
    })

    it('should THROW if verificationMethod has been revoked', async () => {
      let result
      let error = null
      const pastDate = new Date(2020, 11, 17)
        .toISOString()
        .replace(/\.[0-9]{3}/, '')
      const _documentLoader: IDocumentLoader = async url => {
        if (keyId === url) {
          const doc = keyPair.export({
            publicKey: true,
            includeContext: true
          }) as unknown as Record<string, unknown>
          doc.revoked = pastDate
          return {
            contextUrl: null,
            documentUrl: url,
            document: doc
          }
        }
        return documentLoader(url)
      }
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader: _documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeUndefined()
      expect(error).not.toBeNull()
      expect(error?.message).toContain('revoked')
      expect(error?.message).toContain(pastDate)
    })

    it('should THROW if no getVerifier', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          headers: signed,
          documentLoader,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        } as never)
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeUndefined()
      expect(error).not.toBeNull()
      expect(error?.message).toContain('getVerifier')
    })

    it('should THROW if no documentLoader', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        } as never)
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeUndefined()
      expect(error).not.toBeNull()
      expect(error?.message).toContain('documentLoader')
    })

    it('should THROW if there are no headers', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        } as never)
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeUndefined()
      expect(error).not.toBeNull()
      expect(error?.name).toBe('TypeError')
      expect(error?.message).toContain('undefined')
    })

    it('should THROW if keyId can not be dereferenced by the documentLoader', async () => {
      let result
      let error = null
      const _documentLoader: IDocumentLoader = async uri => {
        throw new Error(`NotFoundError: ${uri}`)
      }
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader: _documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(error).not.toBeNull()
      expect(result).toBeUndefined()
      expect(error?.message).toContain('NotFoundError')
    })

    it('should THROW if verificationMethod type is not supported', async () => {
      let result
      let error = null
      const _documentLoader: IDocumentLoader = async uri => {
        if (uri === keyId) {
          const doc = {
            id: uri,
            '@context': ZCAP_CONTEXT_URL,
            controller,
            type: 'AESVerificationKey2001'
          }
          return {
            contextUrl: null,
            documentUrl: uri,
            document: doc
          }
        }
        return documentLoader(uri)
      }
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader: _documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeUndefined()
      expect(error).not.toBeNull()
    })

    it('should NOT verify unless both content-type and digest are set', async () => {
      let result
      let error = null
      delete signed.digest
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(error).toBeNull()
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toContain('digest was not in the request')
    })

    it('should NOT verify if there is no url', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        } as never)
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeDefined()
      expect(error).toBeNull()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('TypeError')
      expect(result?.error?.message).toContain('startsWith')
    })

    it('should NOT verify if host is not in expectedHost', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost: 'not-foo.org',
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeDefined()
      expect(error).toBeNull()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('NotAllowedError')
      expect(result?.error?.message).toBe(
        'Host header contains an unexpected host name.'
      )
    })

    it('should NOT verify if Signature is missing keyId', async () => {
      let result
      let error = null
      // this is just to ensure no keyId is passed in headers
      delete signed.keyid
      const keyIdReplacer = /keyId="[^"]+",/i
      // this will remove keyId from the signature
      // this is where the error should come from
      signed.authorization = signed.authorization!.replace(keyIdReplacer, '')
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeDefined()
      expect(error).toBeNull()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toBe('keyId was not specified')
    })

    it('should NOT verify if Signature is missing created', async () => {
      let result
      let error = null
      const createdReplacer = /created="[^"]+",/i
      // this will remove created from the signature
      // this is where the error should come from
      signed.authorization = signed.authorization!.replace(createdReplacer, '')
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeDefined()
      expect(error).toBeNull()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toBe('created was not in the request')
    })

    it('should NOT verify if Signature is missing expires', async () => {
      let result
      let error = null
      const expiresReplacer = /expires="[^"]+",?/i
      // this will remove created from the signature
      // this is where the error should come from
      signed.authorization = signed.authorization!.replace(expiresReplacer, '')
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(result).toBeDefined()
      expect(error).toBeNull()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toBe('expires was not in the request')
    })

    it('should NOT verify if there is no method', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        } as never)
      } catch (err) {
        error = err as Error
      }
      expect(error).toBeNull()
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('TypeError')
      expect(result?.error?.message).toContain('toLowerCase')
    })

    it('should NOT verify if headers is missing host', async () => {
      let result
      let error = null
      delete signed.host
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(error).toBeNull()
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('NotAllowedError')
      expect(result?.error?.message).toBe(
        'Host header contains an unexpected host name.'
      )
    })

    it('should NOT verify with additionalHeaders not used in Signature', async () => {
      let result
      let error = null
      try {
        result = await verifyCapabilityInvocation({
          additionalHeaders: ['foo'],
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(error).toBeNull()
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toBe('foo was not a signed header')
    })

    it('should NOT verify if headers is missing capability-invocation', async () => {
      let result
      let error = null
      delete signed['capability-invocation']
      try {
        result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          getVerifier,
          documentLoader,
          headers: signed,
          expectedHost,
          expectedAction: 'read',
          expectedRootCapability,
          expectedTarget: invocationResourceUrl
        })
      } catch (err) {
        error = err as Error
      }
      expect(error).toBeNull()
      expect(result).toBeDefined()
      expect(result).toBeTypeOf('object')
      expect(result?.verified).toBe(false)
      expect(result?.error?.name).toBe('SyntaxError')
      expect(result?.error?.message).toBe(
        'capability-invocation was not in the request'
      )
    })
  })
})
