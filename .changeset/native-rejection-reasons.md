---
'@realreel/photo-attest': minor
---

Native rejection messages now reach JS, and gallery write-back failures get their own error codes.

iOS `PhotoAttestError` is now an expo-modules `Exception` subclass. expo-modules-core derives the JS-facing message from `String(reflecting:)` → `debugDescription`, and the base `reason` is the literal `"undefined reason"`, so every `promise.reject(code, message)` in the module was discarding its message — JS saw `CODE: undefined reason (at ExpoModulesCore/Promise.swift:65)` regardless of the real failure. All reject sites now pass the error object itself, and the subclass trims `debugDescription` to the message so nothing leaks native source coordinates into consumer logs.

**Error codes change on several functions.** `overwriteMediaLibraryAsset` failures no longer masquerade as `C2PA_SIGN_FAILED` (signing has already succeeded by the time the write-back runs): new `MEDIA_OVERWRITE_FAILED` for staging and access failures, and iOS-only `MEDIA_OVERWRITE_REJECTED` when PhotoKit validates and refuses the content edit, with the underlying error domain and code in the message (`PHPhotosErrorDomain 3302` is `PHPhotosErrorInvalidResource` — general resource validation; a non-upright render is the cause we have observed, not the only one it covers). `ASSET_NOT_FOUND` semantics are unchanged.

Separately, `deleteKey`, `generateKey`, `getPublicKey` and `generateCSR` throw rather than taking a `Promise`. Their errors previously reached JS as `ERR_UNEXPECTED`; now that the error type is an `Exception`, expo surfaces the real code (`KEY_NOT_FOUND`, `KEY_ALREADY_EXISTS`, `HARDWARE_UNAVAILABLE`, …). Consumers branching on — or alerting on — `ERR_UNEXPECTED` from those four functions need updating.
