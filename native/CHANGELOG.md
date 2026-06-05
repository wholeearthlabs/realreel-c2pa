# @realreel/photo-attest

## 0.1.1

### Patch Changes

- [`cc88a26`](https://github.com/wholeearthlabs/realreel-c2pa/commit/cc88a261247f48d61b5fbc702282b5fdafb5b79b) Thanks [@boojamya](https://github.com/boojamya)! - `overwriteMediaLibraryAsset`: accept SDK-56 `expo-media-library` asset ids.

  The redesigned (SDK 56) `expo-media-library` API changed the format of `Asset.id`: iOS now returns `ph://<localIdentifier>` and Android a `content://…` MediaStore uri (previously a bare PHAsset localIdentifier and a bare numeric MediaStore `_ID`, respectively). `overwriteMediaLibraryAsset` still expected the legacy form, so it could no longer locate the asset and failed with `ASSET_NOT_FOUND`.

  Both platforms now normalize the id before lookup — iOS strips the `ph://` scheme, Android parses the content uri's last path segment to the row id.
