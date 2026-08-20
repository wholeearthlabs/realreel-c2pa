import { describe, expect, it } from 'vitest';

import { normalizeMediaPath } from '../mediaPath';

describe('normalizeMediaPath — plain paths', () => {
  it('returns an absolute path unchanged', () => {
    expect(
      normalizeMediaPath('/storage/emulated/0/DCIM/Camera/IMG_1.jpg'),
    ).toBe('/storage/emulated/0/DCIM/Camera/IMG_1.jpg');
  });

  it('does NOT decode a plain path', () => {
    // No URI here, so `%20` is a literal filename character. Decoding it would
    // invent a file that does not exist — the mirror image of the bug this
    // function fixes.
    expect(normalizeMediaPath('/tmp/report%20final.jpg')).toBe(
      '/tmp/report%20final.jpg',
    );
  });
});

describe('normalizeMediaPath — file:// URIs', () => {
  it('strips the scheme', () => {
    expect(normalizeMediaPath('file:///data/user/0/app/cache/x.jpg')).toBe(
      '/data/user/0/app/cache/x.jpg',
    );
  });

  it('decodes a percent-encoded space in a directory name', () => {
    // The regression this exists for. Android's Quick Share writes received
    // files to `Download/Quick Share/`, and MediaLibrary hands back the URI
    // form via Uri.fromFile, which escapes the space.
    expect(
      normalizeMediaPath(
        'file:///storage/emulated/0/Download/Quick%20Share/capture-1.JPG',
      ),
    ).toBe('/storage/emulated/0/Download/Quick Share/capture-1.JPG');
  });

  it('decodes non-ASCII escapes as UTF-8', () => {
    expect(
      normalizeMediaPath('file:///storage/emulated/0/%C3%89t%C3%A9/a.jpg'),
    ).toBe('/storage/emulated/0/Été/a.jpg');
  });

  it('decodes an escaped literal percent exactly once', () => {
    expect(normalizeMediaPath('file:///tmp/report%2520final.jpg')).toBe(
      '/tmp/report%20final.jpg',
    );
  });

  it('accepts an uppercase scheme', () => {
    expect(normalizeMediaPath('FILE:///tmp/a.jpg')).toBe('/tmp/a.jpg');
  });

  it('drops an iOS PHAsset fragment', () => {
    // `AVURLAsset.url` for a PHAsset video carries `#asset-metadata`, which is
    // not part of the path and leaves the file unopenable if kept.
    expect(
      normalizeMediaPath(
        'file:///var/mobile/Media/DCIM/IMG_2.mov#asset-metadata',
      ),
    ).toBe('/var/mobile/Media/DCIM/IMG_2.mov');
  });

  it('drops a query string', () => {
    expect(normalizeMediaPath('file:///tmp/a.jpg?v=2')).toBe('/tmp/a.jpg');
  });

  it('accepts the RFC 8089 localhost authority', () => {
    expect(normalizeMediaPath('file://localhost/tmp/a.jpg')).toBe('/tmp/a.jpg');
  });
});

describe('normalizeMediaPath — inputs it deliberately leaves alone', () => {
  it('returns a non-local authority unchanged', () => {
    // There is no local filesystem path to extract from a remote host, and
    // silently yielding the relative `share/a.jpg` would produce a baffling
    // error. Handing it back verbatim makes native's "does not exist" message
    // name what the caller actually passed.
    expect(normalizeMediaPath('file://server/share/a.jpg')).toBe(
      'file://server/share/a.jpg',
    );
  });

  it('returns a bare scheme unchanged', () => {
    expect(normalizeMediaPath('file://')).toBe('file://');
  });

  it('falls back to the undecoded path on a malformed escape', () => {
    // decodeURIComponent throws URIError on a `%` not followed by two hex
    // digits. No worse than the naive scheme-strip, and native echoes the path.
    expect(normalizeMediaPath('file:///tmp/100%.jpg')).toBe('/tmp/100%.jpg');
  });

  it('is idempotent on an already-normalized path', () => {
    const once = normalizeMediaPath(
      'file:///storage/emulated/0/Download/Quick%20Share/capture-1.JPG',
    );
    expect(normalizeMediaPath(once)).toBe(once);
  });

  it('returns the empty string unchanged', () => {
    expect(normalizeMediaPath('')).toBe('');
  });
});
