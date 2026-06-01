/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc. and Interop Alliance. All rights reserved.
 */
import { base64, base64urlnopad } from '@scure/base'

/**
 * Standard (RFC 4648) base64 with padding. Used to decode the `signature`
 * parameter from the `Authorization` header, which the signer encodes with
 * padding (`Buffer.toString('base64')` in Node, `btoa`/`toBase64()` in the
 * browser).
 */
export const base64decode = base64

/**
 * RFC 4648 url-safe base64 without padding. Used to decode the gzipped
 * capability from the `capability-invocation` header, which the signer encodes
 * unpadded (`Buffer.toString('base64url')` in Node, `toBase64({ omitPadding:
 * true })` in the browser).
 */
export const base64url = base64urlnopad
