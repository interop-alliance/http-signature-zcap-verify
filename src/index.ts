/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc. and Interop Alliance. All rights reserved.
 */
import { CapabilityInvocation, constants } from '@interop/zcap'
import type {
  InspectCapabilityChain,
  CapabilityInvocationOptions
} from '@interop/zcap'
import {
  parseRequest,
  parseSignatureHeader
} from '@interop/http-signature-header'
import type {
  IVerifier,
  IVerificationMethod,
  IZcap
} from '@interop/data-integrity-core'
import type { IDocumentLoader } from '@interop/data-integrity-core/loader'
import { base64decode, base64url } from './baseX.js'
import pako from 'pako'

/**
 * Matches the leading `scheme:` of an absolute URI per the RFC 3986 scheme
 * grammar (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`). Used to decide
 * whether an invocation `url` is already absolute (any scheme -- `https:`,
 * `did:`, `urn:`, ...) or a relative URL that must be prefixed with the host.
 */
const ABSOLUTE_URI_SCHEME = /^[a-z][a-z0-9+.-]*:/i

/**
 * A jsonld-signatures signature suite instance (or instances) used to verify
 * the capability delegation chain, e.g. `new Ed25519Signature2020()`. Derived
 * from `@interop/zcap`'s public option type, which carries the underlying
 * `LinkedDataProof` type from `@interop/jsonld-signatures` (a dependency this
 * library does not otherwise import).
 */
export type SignatureSuite = NonNullable<CapabilityInvocationOptions['suite']>

/**
 * An async function that dereferences a key id and returns a verifier and the
 * verification method document for that key.
 */
export type GetVerifier = (options: {
  keyId: string
  documentLoader: IDocumentLoader
}) => Promise<{ verifier: IVerifier; verificationMethod: IVerificationMethod }>

/**
 * @param options {object} - Options to use.
 * @param options.url {string} - The url of the request. Used as the invocation
 *   target. An absolute URI (any scheme -- `https:`, `http:`, `did:`, `urn:`,
 *   ...) is used verbatim; a relative url is resolved against the request host
 *   as `https://${host}${url}`.
 * @param options.method {string} - The HTTP request method.
 * @param options.headers {object} - The headers from the request.
 * @param options.getVerifier {GetVerifier} - An async function to
 *   call to get a verifier and verification method for the key ID.
 * @param options.documentLoader {IDocumentLoader} - A jsonld document loader; it
 *   must be able to load the root zcap and any contexts used in the zcap
 *   delegation chain.
 * @param options.expectedHost {string|string[]} - The expected host of the
 *   request.
 * @param options.expectedAction {string} - The expected action of the zcap.
 * @param options.expectedRootCapability {string|string[]} - The expected root
 *   capability of the zcap.
 * @param options.expectedTarget {string} - The expected target of the zcap.
 * @param options.suite {SignatureSuite} - The jsigs signature suite(s) for
 *   verifying the capability delegation chain.
 * @param [options.allowTargetAttenuation=false] {boolean} - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param [options.additionalHeaders=[]] {string[]} - Additional headers
 *   to verify.
 * @param [options.beforeValidatePurpose] {Function} - A function that is
 *   called prior to validating the proof purpose and is passed the purpose
 *   instance, proof meta data, and capability information.
 * @param [options.inspectCapabilityChain] {Function} - A function that can
 *   inspect a capability chain.
 * @param [options.maxChainLength] {number} - The maximum length of the
 *   capability delegation chain.
 * @param [options.maxDelegationTtl] {number} - The maximum milliseconds to
 *   live for a delegated zcap as measured by the time difference between
 *   `expires` and `created` on the delegation proof.
 * @param [options.maxClockSkew=300] {number} - A maximum number of seconds
 *   that clocks may be skewed when checking capability expiration date-times
 *   against `date`, when comparing invocation proof creation time against
 *   delegation proof creation time, and when comparing the capability
 *   invocation expiration time against `now`.
 * @param [options.now=now] {number|Date} - A unix timestamp or an
 *   instance of Date.
 */
export interface VerifyCapabilityInvocationOptions {
  url: string
  method: string
  headers: Record<string, string>
  getVerifier: GetVerifier
  documentLoader: IDocumentLoader
  expectedHost: string | string[]
  expectedAction: string
  expectedRootCapability: string | string[]
  expectedTarget: string
  suite: SignatureSuite
  allowTargetAttenuation?: boolean
  additionalHeaders?: string[]
  beforeValidatePurpose?: (params: {
    purpose: unknown
    proof: unknown
    capability: string | IZcap
    capabilityAction: unknown
  }) => Promise<void> | void
  inspectCapabilityChain?: InspectCapabilityChain
  maxChainLength?: number
  maxClockSkew?: number
  maxDelegationTtl?: number
  now?: number | Date
}

/**
 * The result of a capability invocation verification.
 */
export interface VerifyCapabilityInvocationResult {
  verified: boolean
  error?: Error
  capability?: string | IZcap
  capabilityAction?: unknown
  controller?: string
  dereferencedChain?: IZcap[]
  invoker?: string
  verificationMethod?: IVerificationMethod
}

/**
 * An `Error` decorated with the extra properties this library attaches.
 */
interface VerificationError extends Error {
  host?: string
  expectedHost?: string[]
}

/**
 * Verifies a zcap invocation in the form of an http-signature header.
 *
 * @param options {VerifyCapabilityInvocationOptions} - Options to use.
 *
 * @returns {Promise<VerifyCapabilityInvocationResult>} The result of the
 *   verification.
 */
export async function verifyCapabilityInvocation({
  url,
  method,
  headers,
  getVerifier,
  documentLoader,
  expectedHost,
  expectedAction,
  expectedRootCapability,
  expectedTarget,
  suite,
  additionalHeaders = [],
  allowTargetAttenuation = false,
  beforeValidatePurpose,
  inspectCapabilityChain,
  maxChainLength,
  maxClockSkew = 300,
  maxDelegationTtl,
  now = Math.floor(Date.now() / 1000)
}: VerifyCapabilityInvocationOptions): Promise<VerifyCapabilityInvocationResult> {
  if (now instanceof Date) {
    now = Math.floor(now.getTime() / 1000)
  }
  if (!getVerifier) {
    throw new TypeError(
      '"getVerifier" must be given to dereference the key for verifying ' +
        'the capability invocation signature.'
    )
  }
  if (beforeValidatePurpose && typeof beforeValidatePurpose !== 'function') {
    throw new TypeError('"beforeValidatePurpose" must be a function.')
  }

  // parse http header for signature
  const expectedHeaders = [
    '(key-id)',
    '(created)',
    '(expires)',
    '(request-target)',
    'host',
    'capability-invocation'
  ]
  const reqHeaders = _lowerCaseObjectKeys(headers)
  if (reqHeaders['content-type']) {
    additionalHeaders.push('content-type')
    additionalHeaders.push('digest')
  }
  expectedHeaders.push(...additionalHeaders)
  let parsed
  try {
    // `now` will be used to check against the expiry on the signature using
    // a clock skew of 5 minutes
    parsed = parseRequest(
      { url, method, headers },
      {
        headers: expectedHeaders,
        clockSkew: maxClockSkew,
        now
      }
    )
  } catch (error) {
    return { verified: false, error: error as Error }
  }

  // verify that `host` matches server host
  if (!Array.isArray(expectedHost)) {
    expectedHost = [expectedHost]
  }
  const { host } = reqHeaders
  if (!expectedHost.includes(host as string)) {
    const error = new Error(
      'Host header contains an unexpected host name.'
    ) as VerificationError
    error.name = 'NotAllowedError'
    error.host = host
    error.expectedHost = expectedHost
    return { verified: false, error }
  }

  /* Note: The order in which we run these checks can introduce side channels
  that leak information (e.g., timing). However, we are not presently concerned
  about leaking information about existing capabilities as such leaks do not
  pose any security risk -- and any privacy correlation risk is low if the
  capability identifiers are infeasible to guess. */

  // get parsed parameters from HTTP header and generate signing string
  const {
    keyId,
    signingString,
    params: { created, signature: b64Signature }
  } = parsed

  // verify HTTP signature
  const { verifier, verificationMethod } = await getVerifier({
    keyId,
    documentLoader
  })
  const encoder = new TextEncoder()
  const data = encoder.encode(signingString)
  const signature = base64decode.decode(b64Signature)
  const verified = await verifier.verify({ data, signature })
  if (!verified) {
    const error = new Error('Signature not verified.')
    error.name = 'DataError'
    return { verified: false, error }
  }

  // always dereference the invoked capability to ensure that the system can
  // dereference it authoritatively (which may include ensuring that it is
  // saved in an authorized list, etc.)
  const invocationHeader = reqHeaders['capability-invocation'] as string
  const parsedInvocationHeader = parseSignatureHeader(invocationHeader)
  if (parsedInvocationHeader.scheme !== 'zcap') {
    const error = new Error('Capability invocation scheme must be "zcap".')
    error.name = 'DataError'
    return { verified: false, error }
  }

  let capability = parsedInvocationHeader.params.id as
    | string
    | IZcap
    | undefined
  if (!capability) {
    capability = parsedInvocationHeader.params.capability as string | undefined
    if (capability) {
      try {
        capability = JSON.parse(
          new TextDecoder('utf-8').decode(
            pako.ungzip(base64url.decode(capability))
          )
        )
      } catch {
        const error = new Error(
          'Capability in Capability-Invocation header is improperly encoded.'
        )
        error.name = 'DataError'
        return { verified: false, error }
      }
    }
    if (!(capability as { parentCapability?: unknown }).parentCapability) {
      const error = new Error(
        'A root capability must be invoked using only its ID.'
      )
      error.name = 'DataError'
      return { verified: false, error }
    }
  }
  if (!capability) {
    const error = new Error(
      'Capability not present in Capability-Invocation header.'
    )
    error.name = 'DataError'
    return { verified: false, error }
  }

  // check capability invocation
  const purpose = new CapabilityInvocation({
    allowTargetAttenuation,
    // `date` is in milliseconds and `now` is in seconds, so convert
    date: now * 1000,
    expectedAction,
    expectedRootCapability,
    expectedTarget,
    inspectCapabilityChain,
    maxChainLength,
    maxClockSkew,
    maxDelegationTtl,
    suite
  })
  // invocation target must match absolute url
  let invocationTarget
  // An absolute URI is used verbatim, regardless of scheme: `https:`/`http:`
  // for HTTP targets, but also `did:`, `urn:`, etc. so that DID-relative and
  // other non-HTTP invocation targets are not rewritten into an HTTPS url.
  // Match the RFC 3986 scheme grammar (`ALPHA *( ALPHA / DIGIT / "+" / "-" /
  // "." )` followed by `:`) rather than a bare colon: that keeps non-conformant
  // relative URLs that carry an unencoded colon in a path segment (e.g.
  // `/foo:bar`) classified as relative, since they do not begin with a scheme.
  if (ABSOLUTE_URI_SCHEME.test(url)) {
    invocationTarget = url
  } else {
    // If encountering a relative URL, assume HTTPS
    invocationTarget = `https://${headers.host}${url}`
  }

  const capabilityAction = parsedInvocationHeader.params.action
  const proof = {
    '@context': constants.ZCAP_CONTEXT_URL,
    capability,
    capabilityAction,
    // use second precision for created date
    created: new Date(Number(created) * 1000).toISOString().slice(0, -5) + 'Z',
    invocationTarget,
    verificationMethod: keyId
  }
  if (beforeValidatePurpose) {
    await beforeValidatePurpose({
      purpose,
      proof,
      capability,
      capabilityAction
    })
  }
  const result = await purpose.validate(proof, {
    verificationMethod,
    documentLoader
  })
  const { valid, error, dereferencedChain } = result
  if (!valid) {
    return { verified: false, error }
  }

  const controller = verificationMethod.controller || verificationMethod.id
  return {
    capability,
    capabilityAction,
    controller,
    dereferencedChain,
    invoker: controller,
    verificationMethod,
    verified: true
  }
}

function _lowerCaseObjectKeys(obj: Record<string, string>): Record<
  string,
  string
> {
  const newObject: Record<string, string> = {}
  for (const [key, value] of Object.entries(obj)) {
    newObject[key.toLowerCase()] = value
  }
  return newObject
}
