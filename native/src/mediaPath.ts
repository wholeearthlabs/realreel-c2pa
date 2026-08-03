/**
 * Accept either a plain absolute filesystem path or a local `file://` URI, and
 * return the filesystem path native expects (`File(path)` on Android,
 * `URL(fileURLWithPath:)` on iOS).
 *
 * Why the module accepts both: the values callers have on hand are URIs
 * (`MediaLibrary.Asset.getUri()`, `ImagePicker`, `Camera`, `FileSystem`), and
 * both platforms percent-encode them (`Uri.fromFile` / `URL.absoluteString`).
 * Stripping the scheme alone leaves `%20` for every space, so any capture under
 * a spaced directory — Android's Quick Share writes to `Download/Quick Share/`
 * — resolves to a file that does not exist. Done here rather than in Swift and
 * Kotlin so there is one implementation to keep correct, not two.
 *
 * A plain path is returned unchanged and is **never** decoded: it is already
 * the on-disk literal, and a file genuinely named `50%20off.jpg` would be
 * rewritten to one that doesn't exist. This also keeps a round-trip lossless,
 * since native hands paths back in bare form (`signedMediaPath`).
 *
 * A `file://` URI with a non-local authority (`file://host/share/x.jpg`) has no
 * local path to extract, so it too is returned unchanged and native names it
 * verbatim in the "does not exist" message.
 */
export function normalizeMediaPath(pathOrUri: string): string {
  // A literal `#` or `?` in a filename is `%23` / `%3F` in a well-formed URI,
  // so anything past them is a fragment/query. iOS appends `#asset-metadata` to
  // PHAsset video URLs, so this is a real input.
  const withoutSuffix = pathOrUri.replace(/[?#].*$/, '');

  // `file:///path` and `file://localhost/path` are the two RFC 8089 spellings
  // of a local file; the leading `/` anchor rejects any other authority.
  const path = /^file:\/\/(?:localhost)?(?<path>\/.*)$/i.exec(withoutSuffix)
    ?.groups?.path;
  if (path === undefined) return pathOrUri;

  try {
    return decodeURIComponent(path);
  } catch {
    // URIError: a `%` not followed by two hex digits. Undecoded is no worse
    // than the naive scheme-strip this replaces, and native echoes the path.
    return path;
  }
}
