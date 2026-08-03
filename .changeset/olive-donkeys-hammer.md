---
'@realreel/photo-attest': minor
---

Accept `file://` URIs for every path argument, and report a missing parent capture as `STAGE1_PARENT_UNREADABLE`.

**Path arguments now take either a plain absolute filesystem path or a local `file://` URI.** Expo's `MediaLibrary.Asset.getUri()`, `ImagePicker`'s `assets[].uri`, `Camera`'s `uri` and `FileSystem`'s `File.uri` all hand back percent-encoded URIs (`Uri.fromFile` on Android, `URL.absoluteString` on iOS), while native needs a bare path. Callers bridging the two by stripping the scheme alone were left with `%20` wherever a path contained a space — and a file that doesn't exist. The failure was easy to miss: every other library in a typical pipeline is URI-aware, so the same file opened fine everywhere else and only the sign failed. Directories with spaces are ordinary in practice (Android Quick Share writes to `Download/Quick Share/`).

Conversion happens once in the TS bridge (`normalizeMediaPath`, now exported): query/fragment dropped — including the `#asset-metadata` iOS appends to PHAsset video URLs — then percent-decoded. A plain path is passed through untouched and is never decoded, so a literal `%` in a filename still works.

**`signC2PAUpload` and `signTimestampUpdateManifest` now throw `STAGE1_PARENT_UNREADABLE`, not `C2PA_SIGN_FAILED`, when the parent file is missing.** This matches what that code already documents ("the parent's embedded JUMBF cannot be read (**missing**, corrupted, …)") and what the same functions already throw when the parent's manifest is unreadable. The distinction matters to callers: an absent parent is the user's gallery asset (recapture or re-pick), whereas `C2PA_SIGN_FAILED` means our own signing step broke (retry). Branch on `STAGE1_PARENT_UNREADABLE` if you were matching `C2PA_SIGN_FAILED` for this case.
