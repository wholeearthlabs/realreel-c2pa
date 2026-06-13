// Tests for src/derive-metadata.ts. Entry derivation is pinned against real
// committed fixtures; assertion sourcing (lat/lon, locationLabel) is unit-tested
// with synthetic active manifests fed alongside the real bytes, so those
// branches are covered before the native locationLabel signing ships.
//
// Fixtures: realreel-uploaded.jpg — a none/general photo (no GPS, no label).
// realreel-capture.mov — a real RealReel capture (HEVC/AAC, com.realreel.comment,
// no location atom) for entry shape. synthetic-container-gps.mp4 — a tiny fully
// synthetic clip with a FAKE location atom (no personal data); its only job is
// to prove the container coordinate is never read into entries.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { deriveMetadata } from "../src/derive-metadata.js";
import type { ManifestShape } from "../src/c2pa-shape.js";

const fixtures = (name: string) => resolve(import.meta.dirname, "fixtures", name);

const photoBytes = await readFile(fixtures("realreel-uploaded.jpg"));
const videoBytes = await readFile(fixtures("realreel-capture.mov"));
const videoGpsBytes = await readFile(fixtures("synthetic-container-gps.mp4"));

/** Any entry whose label looks like it could carry a coordinate. The whole
 *  point of the GPS-from-assertion design is that NONE survive into entries. */
const hasGeoEntry = (entries: Array<{ label: string }>) =>
  entries.some((e) => /location|gps|coordinate|iso6709|xyz|geo/i.test(e.label));

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const byKey = (entries: Array<{ label: string; value: string }>) =>
  new Map(entries.map((e) => [norm(e.label), e.value]));

describe("derivePhotoMetadata — real RealReel JPEG (none/general capture)", () => {
  it("derives display-keyed entries from the validated bytes", async () => {
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: undefined,
    });
    const m = byKey(d.entries);

    // Camera identity + exposure — the headline fields the display reads.
    expect(m.get("make")).toBe("Google");
    expect(m.get("model")).toBe("Pixel 10");
    expect(m.get("fnumber")).toBe("1.7");
    expect(m.get("iso")).toBe("57"); // exifr "ISO" → display alternate of isospeedratings
    expect(m.get("datetimeoriginal")).toBe("2026:05:28 12:46:28");
    // The RealReel build breadcrumb survives as a parseable JSON comment.
    expect(m.get("usercomment")).toContain('"realreel"');

    expect(d.metadataType).toBe("exif");
  });

  it("dispatches on the verified BYTES, not a client mimeType — a lying mimeType can't flip metadataType", async () => {
    // JPEG bytes + a spoofed video mimeType → still derived as a photo (the
    // stored metadata_type is bound to the upload, not the client string).
    const photo = await deriveMetadata({ assetBytes: photoBytes, mimeType: "video/mp4", active: undefined });
    expect(photo.metadataType).toBe("exif");
    expect(photo.entries.some((e) => norm(e.label) === "make")).toBe(true);

    // MP4 bytes + a spoofed photo mimeType → still derived as a video.
    const video = await deriveMetadata({ assetBytes: videoGpsBytes, mimeType: "image/jpeg", active: undefined });
    expect(video.metadataType).toBe("video");
  });

  it("never emits a coordinate-bearing entry, and reports no location when the manifest carries none", async () => {
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: undefined,
    });
    expect(hasGeoEntry(d.entries)).toBe(false);
    expect(d.latitude).toBeNull();
    expect(d.longitude).toBeNull();
    expect(d.location).toBeNull();
  });

  it("drops binary byte-map tags (e.g. ExifVersion) rather than emitting garbage", async () => {
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: undefined,
    });
    // Every value is a non-empty scalar string — no "[object Object]" / control
    // bytes that postgres jsonb would reject.
    for (const e of d.entries) {
      expect(typeof e.value).toBe("string");
      expect(e.value.length).toBeGreaterThan(0);
      // eslint-disable-next-line no-control-regex
      expect(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(e.value)).toBe(false);
    }
  });
});

describe("derivePhotoMetadata — lat/lon + location from the signed assertion", () => {
  // Synthetic Stage-2 active manifest: signed precise GPS in stds.exif + the
  // signed city label in org.realreel.upload. The bytes are the real (GPS-less)
  // fixture — only the assertion sourcing is under test.
  const precise: ManifestShape = {
    assertions: [
      {
        label: "stds.exif",
        data: {
          // Signed decimal degrees already carry the sign; the Ref letters are
          // cosmetic. A southern/western fixture proves we don't double-negate.
          "exif:GPSLatitude": "-34.2931",
          "exif:GPSLatitudeRef": "S",
          "exif:GPSLongitude": "-119.2974",
          "exif:GPSLongitudeRef": "W",
        },
      },
      { label: "org.realreel.upload", data: { locationLabel: "Ventura, CA" } },
    ],
  };

  it("reads signed coords directly (no Ref re-application) and the signed label", async () => {
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: precise,
    });
    expect(d.latitude).toBeCloseTo(-34.2931, 4);
    expect(d.longitude).toBeCloseTo(-119.2974, 4);
    expect(d.location).toBe("Ventura, CA");
    // Coords come from the assertion, never as an entry.
    expect(hasGeoEntry(d.entries)).toBe(false);
  });

  it("treats a half coordinate pair (lat without lon) as absent", async () => {
    const half: ManifestShape = {
      assertions: [{ label: "stds.exif", data: { "exif:GPSLatitude": "34.0" } }],
    };
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: half,
    });
    expect(d.latitude).toBeNull();
    expect(d.longitude).toBeNull();
  });

  it("rejects an out-of-range coordinate", async () => {
    const bad: ManifestShape = {
      assertions: [
        {
          label: "stds.exif",
          data: { "exif:GPSLatitude": "999", "exif:GPSLongitude": "10" },
        },
      ],
    };
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: bad,
    });
    expect(d.latitude).toBeNull();
  });

  it("emits a general-location label with NO coords (general upload mode)", async () => {
    const general: ManifestShape = {
      assertions: [
        { label: "stds.exif", data: {} }, // GPS redacted
        { label: "org.realreel.upload", data: { locationLabel: "Phoenix, AZ" } },
      ],
    };
    const d = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: general,
    });
    expect(d.latitude).toBeNull();
    expect(d.longitude).toBeNull();
    expect(d.location).toBe("Phoenix, AZ");
  });

  it("drops a control-byte-bearing label and clamps an overlong one (single-trust-boundary sanitation)", async () => {
    const withControl: ManifestShape = {
      assertions: [{ label: "org.realreel.upload", data: { locationLabel: "Phoenix\x00, AZ" } }],
    };
    const dropped = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: withControl,
    });
    expect(dropped.location).toBeNull();

    const overlong: ManifestShape = {
      assertions: [{ label: "org.realreel.upload", data: { locationLabel: "A".repeat(500) } }],
    };
    const clamped = await deriveMetadata({
      assetBytes: photoBytes,
      mimeType: "image/jpeg",
      active: overlong,
    });
    expect(clamped.location?.length).toBe(120);
  });
});

describe("deriveVideoMetadata — real RealReel capture (.mov)", () => {
  // Synthetic Stage-2 active manifest with signed IPTC coords + label.
  const activeVideo: ManifestShape = {
    assertions: [
      {
        label: "stds.iptc",
        data: {
          "Iptc4xmpExt:LocationCreated": [
            { "exif:GPSLatitude": "34.2931", "exif:GPSLongitude": "-119.2974" },
          ],
        },
      },
      { label: "org.realreel.upload", data: { locationLabel: "Ventura, CA" } },
    ],
  };

  it("derives the technical tail with the native extractor's labels", async () => {
    const d = await deriveMetadata({
      assetBytes: videoBytes,
      mimeType: "video/quicktime",
      active: activeVideo,
    });
    const m = byKey(d.entries);

    // Rotation-corrected display dims: the .mov is a portrait capture (90/270
    // display matrix), so coded 1920×1080 → displayed 1080×1920.
    expect(m.get("resolution")).toBe("1080 × 1920");
    expect(m.get("framerate")).toMatch(/fps$/);
    expect(m.get("videocodec")).toBe("hevc"); // display prettyCodec → "H.265"
    expect(m.get("audiocodec")).toBe("aac");
    expect(m.get("audiosamplerate")).toBe("48000 Hz");
    expect(m.get("audiochannels")).toBe("1");
    expect(m.get("colorstandard")).toBe("BT.709");
    expect(m.has("comrealreelcomment")).toBe(true);
    expect(d.metadataType).toBe("video");
  });

  it("reads lat/lon from stds.iptc and the label from upload", async () => {
    const d = await deriveMetadata({
      assetBytes: videoBytes,
      mimeType: "video/quicktime",
      active: activeVideo,
    });
    expect(d.latitude).toBeCloseTo(34.2931, 4);
    expect(d.longitude).toBeCloseTo(-119.2974, 4);
    expect(d.location).toBe("Ventura, CA");
  });

  it("reports no location when the Stage-2 manifest carries no IPTC coords / label", async () => {
    const d = await deriveMetadata({
      assetBytes: videoBytes,
      mimeType: "video/quicktime",
      active: undefined,
    });
    expect(hasGeoEntry(d.entries)).toBe(false);
    expect(d.latitude).toBeNull();
    expect(d.longitude).toBeNull();
    expect(d.location).toBeNull();
  });
});

describe("deriveVideoMetadata — container GPS atom is never read", () => {
  // synthetic-container-gps.mp4 carries a FAKE ISO-6709 `location` atom in its
  // container. The explicit-allowlist mapping never reads it, and the GPS scrub
  // is the backstop — so even with a populated container coordinate, the only
  // lat/lon that can surface is the signed stds.iptc one (here: none).
  it("never surfaces the container's coordinate — coords come only from the assertion", async () => {
    const withIptc: ManifestShape = {
      assertions: [
        {
          label: "stds.iptc",
          data: {
            "Iptc4xmpExt:LocationCreated": [
              { "exif:GPSLatitude": "40.0", "exif:GPSLongitude": "-70.0" },
            ],
          },
        },
      ],
    };
    const d = await deriveMetadata({
      assetBytes: videoGpsBytes,
      mimeType: "video/mp4",
      active: withIptc,
    });
    // No entry leaks the container's +12.3456+098.7654/ atom...
    expect(hasGeoEntry(d.entries)).toBe(false);
    expect(d.entries.some((e) => e.value.includes("12.3456") || e.value.includes("98.7654"))).toBe(false);
    // ...and the only coords are the signed-assertion ones.
    expect(d.latitude).toBeCloseTo(40.0, 4);
    expect(d.longitude).toBeCloseTo(-70.0, 4);
  });

  it("with no assertion coords, a container GPS atom yields null lat/lon", async () => {
    const d = await deriveMetadata({
      assetBytes: videoGpsBytes,
      mimeType: "video/mp4",
      active: undefined,
    });
    expect(hasGeoEntry(d.entries)).toBe(false);
    expect(d.latitude).toBeNull();
    expect(d.longitude).toBeNull();
  });
});
