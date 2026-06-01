/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc. and Interop Alliance. All rights reserved.
 */
import { securityLoader } from '@interop/security-document-loader'
import type { DocumentLoader } from '../../src/index.js'

/**
 * A document loader preloaded with the security/zcap/key contexts bundled by
 * `@interop/security-document-loader` (zcap, aes-key-wrapping, sha256-hmac,
 * ed25519, did, multikey, data-integrity, etc.).
 */
export const securityDocumentLoader: DocumentLoader = securityLoader().build()
