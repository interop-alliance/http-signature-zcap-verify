import { test, expect } from '@playwright/test'

// Vite serves and transforms the TypeScript fixture on the fly. The specifier
// is held in a variable so TypeScript does not try to resolve this
// browser-only runtime path at compile time.
const fixturePath = '/test/browser/verify-fixture.ts'

test('verifies a capability invocation in the browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const verified = await page.evaluate(async path => {
    const { runHappyPath } = await import(/* @vite-ignore */ path)
    return runHappyPath()
  }, fixturePath)
  expect(verified).toBe(true)
})

test('resolves a bundled context via the real securityLoader', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const resolved = await page.evaluate(async path => {
    const { loaderResolvesBundledContext } = await import(
      /* @vite-ignore */ path
    )
    return loaderResolvesBundledContext()
  }, fixturePath)
  expect(resolved).toBe(true)
})
