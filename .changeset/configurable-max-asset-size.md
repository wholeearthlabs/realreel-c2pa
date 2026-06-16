---
"@realreel/verifier": patch
---

Make the `/verify` asset fetch/buffer ceiling configurable. The size gate
previously hard-coded a 50 MiB limit (`MAX_ASSET_BYTES`); it now reads
`config.maxAssetBytes`, overridable via the optional `MAX_ASSET_MIB` env var
and defaulting to 50 (so default behavior is unchanged). Set it to match the
asset-storage bucket's `file_size_limit` when that exceeds 50 MiB — otherwise
an upload whose size lands in the gap band passes Storage and then fails
verification as oversize. Validated at startup: non-positive or above a 512 MiB
sanity ceiling throws.
