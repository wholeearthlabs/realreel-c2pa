// Derive the displayed photo/video metadata from the VERIFIED upload — the
// single trust boundary for those values. The edge function inserts exactly
// what this returns; nothing the client sends. Two sources, one uniform output
// (DerivedMetadata):
//
//   1. The validated bytes, byte-probed (photos: exifr; video: ffprobe, since
//      the moov-box technical fields aren't in the manifest). The bytes are
//      hash-bound by the already-verified manifest, so the probe is trustworthy
//      to the same ceiling as an assertion.
//   2. The signed assertions, which a byte probe must NOT override:
//        - lat/lon: ONLY from the signed assertion (stds.exif / stds.iptc). The
//          signer writes GPS only for "precise"; absence = not shared. GPS is
//          also SCRUBBED from the byte probe (GPS_SCRUB) so a byte-level leak
//          — e.g. ffprobe's container `location` atom — can't resurrect it.
//        - location string: from the signed org.realreel.upload `locationLabel`
//          (general + precise). The client reverse-geocodes; we just sign it.
//          The verifier makes no outbound call.
//
// Honesty bound: this raises trust to "unaltered, from an enrolled device", NOT
// "camera-attested" — the assertions are authored at Stage 2 by the app from
// the file it built (a tampered-but-attested build could still sign false
// metadata; that residual is gated by App Attest / Play Integrity).

import exifr from "exifr";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { ManifestShape, AssertionShape } from "./c2pa-shape.js";

const execFileAsync = promisify(execFile);

export interface DerivedEntry {
  label: string;
  value: string;
}

export interface DerivedMetadata {
  /** [{label,value}] in the shape shared/mediaDetails.ts consumes. Labels are
   *  the parser's native keys; the display layer keys off their normalized
   *  form. */
  entries: DerivedEntry[];
  /** Signed precise latitude (decimal degrees), or null when not shared. */
  latitude: number | null;
  /** Signed precise longitude (decimal degrees), or null when not shared. */
  longitude: number | null;
  /** Signed city/state label (general + precise), or null. */
  location: string | null;
  /** The media.metadata_type column value (display keys off media.is_video). */
  metadataType: "exif" | "video";
}

// A byte-probe field whose key matches this is dropped from `entries`: GPS is
// authoritative from the signed assertion only (see module header). Tested
// against the raw probe key, case-insensitive. "iso6709" (not bare "iso") so the
// EXIF "ISO" sensitivity tag is NOT scrubbed.
const GPS_SCRUB = /location|gps|coordinate|iso6709|xyz|geo/i;

// Some camera pipelines (e.g. Pixel HDR+) stash binary blobs under string-typed
// EXIF tags; control bytes (bar tab/LF/CR) make postgres jsonb reject the INSERT
// and render as garbage, so such a string is dropped whole (mirrors
// utils/exifFormat.ts formatValue).
// eslint-disable-next-line no-control-regex
const CONTROL_BYTES = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

/** Find an assertion's `data` payload by label in a manifest. */
function assertionData(
  manifest: ManifestShape | undefined,
  label: string,
): Record<string, unknown> | undefined {
  const a = manifest?.assertions?.find(
    (x: AssertionShape) => x.label === label,
  );
  const data = a?.data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : undefined;
}

/** Coerce a manifest GPS value (c2pa serializes numbers as strings) to a
 *  finite, in-range decimal degree, or null. The value is signed — the sign
 *  carries direction, so the EXIF *Ref letters are cosmetic and never
 *  re-applied (re-applying would double-negate the southern/western
 *  hemisphere). */
function toCoord(v: unknown, max: number): number | null {
  // Number() (not parseFloat) so trailing garbage like "34.0abc" rejects; guard
  // the empty string first, since Number("") is 0.
  let n: number;
  if (typeof v === "number") n = v;
  else if (typeof v === "string" && v.trim() !== "") n = Number(v);
  else n = NaN;
  if (!Number.isFinite(n) || Math.abs(n) > max) return null;
  return n;
}

/** Gate a coordinate pair: both present or both null (a half pair = absent). */
function coordPair(lat: number | null, lon: number | null): {
  latitude: number | null;
  longitude: number | null;
} {
  const complete = lat != null && lon != null;
  return { latitude: complete ? lat : null, longitude: complete ? lon : null };
}

// Bound on the place label that reaches media.location + the public embed. A
// real "City, Region, Country" is well under this; longer is pathological.
const MAX_LOCATION_LABEL = 120;

/** The signed city/state label from org.realreel.upload, or null. Sanitized to
 *  the same bar as every other displayed value (the verifier is the single
 *  trust boundary): a control-byte-bearing label — only reachable via a
 *  tampered build — is dropped (a NUL would fail the postgres `text` INSERT and
 *  the rest render as garbage), and the length is clamped. */
function readLocationLabel(active: ManifestShape | undefined): string | null {
  const up = assertionData(active, "org.realreel.upload");
  const label = up?.["locationLabel"];
  if (typeof label !== "string") return null;
  const trimmed = label.trim();
  if (!trimmed || CONTROL_BYTES.test(trimmed)) return null;
  return trimmed.slice(0, MAX_LOCATION_LABEL);
}

/** Format a raw exifr value to a display string, or null to drop the entry.
 *  Mirrors utils/exifFormat.ts formatValue: numbers stringified, blank/binary
 *  strings dropped, non-scalar (byte maps like ExifVersion) dropped. */
function formatExifValue(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : null;
  if (typeof v === "string") {
    const t = v.trim();
    if (t.length === 0 || CONTROL_BYTES.test(t)) return null;
    return t;
  }
  // exifr with reviveValues:false keeps EXIF dates as "YYYY:MM:DD HH:MM:SS"
  // strings; this guards an unexpected Date all the same.
  if (v instanceof Date) {
    const p = (n: number) => String(n).padStart(2, "0");
    return (
      `${v.getUTCFullYear()}:${p(v.getUTCMonth() + 1)}:${p(v.getUTCDate())} ` +
      `${p(v.getUTCHours())}:${p(v.getUTCMinutes())}:${p(v.getUTCSeconds())}`
    );
  }
  // Arrays / byte-maps (e.g. ExifVersion) / objects — nothing a viewer renders.
  return null;
}

/**
 * Photo: byte-probe EXIF with exifr (gps:false — we never read coordinates from
 * the bytes), build display entries, take lat/lon from the signed stds.exif
 * assertion and the location label from org.realreel.upload.
 */
async function derivePhotoMetadata(
  assetBytes: Buffer,
  active: ManifestShape | undefined,
): Promise<DerivedMetadata> {
  // exifr accepts boolean block toggles at runtime, but its bundled .d.ts types
  // them as object-only — cast to the parse() parameter type.
  const exifrOptions = {
    tiff: true,
    ifd0: true,
    exif: true,
    interop: true,
    ifd1: false,
    gps: false, // coordinates come from the signed assertion, never here
    makerNote: false, // raw firmware binary
    userComment: true,
    mergeOutput: true,
    translateKeys: true,
    translateValues: true,
    reviveValues: false, // keep EXIF dates as parseable strings, numbers raw
  } as unknown as Parameters<typeof exifr.parse>[1];

  let parsed: Record<string, unknown> = {};
  try {
    parsed = ((await exifr.parse(assetBytes, exifrOptions)) as Record<string, unknown> | undefined) ?? {};
  } catch {
    // No/malformed EXIF → empty entries; the manifest was already verified.
    parsed = {};
  }

  const entries: DerivedEntry[] = [];
  for (const [key, raw] of Object.entries(parsed)) {
    if (GPS_SCRUB.test(key)) continue;
    let value = formatExifValue(raw);
    if (value === null) continue;
    // Focal length carries a unit (matches the old client extractor's "4.5 mm").
    if (key === "FocalLength" || key === "FocalLengthIn35mmFormat") value = `${value} mm`;
    entries.push({ label: key, value });
  }

  const exif = assertionData(active, "stds.exif");
  return {
    entries,
    ...coordPair(toCoord(exif?.["exif:GPSLatitude"], 90), toCoord(exif?.["exif:GPSLongitude"], 180)),
    location: readLocationLabel(active),
    metadataType: "exif",
  };
}

interface FfprobeStream {
  codec_type?: string;
  codec_name?: string;
  profile?: string;
  width?: number;
  height?: number;
  r_frame_rate?: string;
  bit_rate?: string;
  sample_rate?: string;
  channels?: number;
  color_space?: string;
  color_transfer?: string;
  color_primaries?: string;
  side_data_list?: Array<{ rotation?: number }>;
  tags?: Record<string, string>;
}
interface FfprobeJson {
  streams?: FfprobeStream[];
  format?: { bit_rate?: string; size?: string; tags?: Record<string, string> };
}

/** ffprobe color_primaries/space → the native extractor's Color Standard label. */
function colorStandard(s: FfprobeStream): string | null {
  const v = (s.color_primaries || s.color_space || "").toLowerCase();
  if (!v) return null;
  if (v.includes("2020")) return "BT.2020";
  if (v.includes("709")) return "BT.709";
  if (v.includes("601") || v.includes("170m") || v.includes("470bg") || v.includes("smpte-c") || v.includes("ebu"))
    return "BT.601";
  return `Unknown (${s.color_primaries || s.color_space})`;
}

/** ffprobe color_transfer → the native extractor's Color Transfer label. */
function colorTransfer(s: FfprobeStream): string | null {
  const v = (s.color_transfer || "").toLowerCase();
  if (!v) return null;
  if (v.includes("2084") || v.includes("pq")) return "PQ (HDR10)";
  if (v.includes("b67") || v.includes("hlg")) return "HLG";
  if (v.includes("709") || v.includes("170m") || v.includes("iec61966") || v.includes("601") || v.includes("bt470"))
    return "SDR";
  return `Unknown (${s.color_transfer})`;
}

/** "30/1" → 30.00; null when unparseable or zero-denominator. */
function frameRate(r: string | undefined): number | null {
  if (!r) return null;
  const m = r.match(/^(\d+)\/(\d+)$/);
  if (!m) return null;
  const num = Number(m[1]);
  const den = Number(m[2]);
  if (!den) return null;
  return num / den;
}

/**
 * Video: probe the validated MP4 bytes with ffprobe (the technical fields live
 * only in the hash-bound moov boxes, not the manifest), map to the native
 * extractor's entry labels, take lat/lon from the signed stds.iptc
 * LocationCreated and the location label from org.realreel.upload.
 *
 * Entries are an explicit allowlist — we never dump ffprobe's full field set
 * (that would surface the container `location` atom and other noise). GPS is
 * read from the assertion only; the container location is never touched.
 */
async function deriveVideoMetadata(
  assetBytes: Buffer,
  active: ManifestShape | undefined,
): Promise<DerivedMetadata> {
  const entries: DerivedEntry[] = [];
  const tmpPath = join(tmpdir(), `rr-verify-${randomUUID()}.mp4`);
  let probe: FfprobeJson = {};
  try {
    await writeFile(tmpPath, assetBytes);
    const { stdout } = await execFileAsync(
      "ffprobe",
      ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", tmpPath],
      // timeout: the asset is attacker-influenced (only hash-bound, not
      // moov-shape-constrained); a crafted MP4 that hangs ffprobe must not pin
      // a worker. On timeout execFile rejects → the catch degrades to empty.
      { maxBuffer: 8 * 1024 * 1024, timeout: 10_000, killSignal: "SIGKILL" },
    );
    probe = JSON.parse(stdout) as FfprobeJson;
  } catch {
    // Non-probeable input or no ffprobe → empty technical tail; the manifest
    // was already verified, so the row is still valid.
    probe = {};
  } finally {
    await unlink(tmpPath).catch(() => {});
  }

  const streams = probe.streams ?? [];
  const video = streams.find((s) => s.codec_type === "video");
  const audio = streams.find((s) => s.codec_type === "audio");
  const fmt = probe.format ?? {};

  if (video) {
    // Resolution, rotation-corrected to display dimensions (a 90/270 rotation
    // swaps width/height) — matches the native extractor.
    const rot = video.side_data_list?.find((d) => typeof d.rotation === "number")?.rotation ?? 0;
    const swap = Math.abs(rot) % 180 === 90;
    const w = video.width;
    const h = video.height;
    if (typeof w === "number" && typeof h === "number") {
      entries.push({ label: "Resolution", value: swap ? `${h} × ${w}` : `${w} × ${h}` });
    }
    if (rot) entries.push({ label: "Rotation", value: `${((Math.round(rot) % 360) + 360) % 360}°` });

    const fps = frameRate(video.r_frame_rate);
    if (fps != null) entries.push({ label: "Frame Rate", value: `${fps.toFixed(2)} fps` });

    // Stream bitrate, falling back to the container's (video+audio+overhead)
    // when the stream omits it — matches the native extractor.
    const vbr = Number(video.bit_rate ?? fmt.bit_rate);
    if (Number.isFinite(vbr) && vbr > 0)
      entries.push({ label: "Video Bitrate", value: `${(vbr / 1_000_000).toFixed(2)} Mbps` });

    if (video.codec_name) entries.push({ label: "Video Codec", value: video.codec_name });
    if (video.profile) entries.push({ label: "Video Codec Profile", value: video.profile });

    const cs = colorStandard(video);
    if (cs) entries.push({ label: "Color Standard", value: cs });
    const ct = colorTransfer(video);
    if (ct) entries.push({ label: "Color Transfer", value: ct });
  }

  if (audio) {
    if (audio.codec_name) entries.push({ label: "Audio Codec", value: audio.codec_name });
    if (audio.profile) entries.push({ label: "Audio Codec Profile", value: audio.profile });
    if (audio.sample_rate) entries.push({ label: "Audio Sample Rate", value: `${audio.sample_rate} Hz` });
    if (typeof audio.channels === "number")
      entries.push({ label: "Audio Channels", value: String(audio.channels) });
  }

  // "Creation Time (MP4)" — mirrors the native Android label. ffprobe normalizes
  // the container timestamp to UTC ("2026-05-21T23:50:12.000000Z"); we strip the
  // fractional seconds + zone to a clean "YYYY-MM-DD HH:MM:SS". Note this is UTC
  // wall-clock, not the capture device's local zone (unknowable server-side).
  const creation = fmt.tags?.["creation_time"];
  if (creation) {
    const m = creation.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
    entries.push({
      label: "Creation Time (MP4)",
      value: m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}` : creation,
    });
  }

  const size = Number(fmt.size);
  if (Number.isFinite(size) && size > 0) {
    const mb = size / (1024 * 1024);
    entries.push({ label: "File size", value: `${mb.toFixed(1)} MB` });
  }

  // The RealReel capture breadcrumb ({realreel:{version,platform}}) drives the
  // "with RealReel" subline + video source line in the display. Kept verbatim
  // (the display pretty-prints + reads its namespace).
  const comment = fmt.tags?.["com.realreel.comment"];
  if (comment) {
    const value = formatExifValue(comment);
    if (value !== null) entries.push({ label: "com.realreel.comment", value });
  }

  const iptc = assertionData(active, "stds.iptc");
  const created = iptc?.["Iptc4xmpExt:LocationCreated"];
  const loc =
    Array.isArray(created) && created[0] && typeof created[0] === "object"
      ? (created[0] as Record<string, unknown>)
      : undefined;

  return {
    // GPS_SCRUB filter for parity with the photo path: the labels above are all
    // hardcoded (so a no-op today), but it keeps the scrub a universal backstop
    // if a future field ever sources a label from the probe.
    entries: entries.filter((e) => !GPS_SCRUB.test(e.label)),
    ...coordPair(toCoord(loc?.["exif:GPSLatitude"], 90), toCoord(loc?.["exif:GPSLongitude"], 180)),
    location: readLocationLabel(active),
    metadataType: "video",
  };
}

/** Photo vs video from the verified BYTES (magic numbers), not the client
 *  mimeType — the metadataType we store must be bound to the upload, like every
 *  other displayed value. ISOBMFF (mp4/mov) carries an `ftyp` box at offset 4;
 *  JPEG starts FF D8 FF. Falls back to the mimeType hint when inconclusive. */
function isVideoUpload(bytes: Buffer, mimeType: string): boolean {
  if (bytes.length >= 12 && bytes.toString("latin1", 4, 8) === "ftyp") return true;
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return false;
  return mimeType.toLowerCase().startsWith("video/");
}

/**
 * Derive displayed metadata from a verified upload. `active` is the Stage-2
 * (RealReel-signed) active manifest — the uniform derivation source (it carries
 * stds.exif / stds.iptc even for a wrapped Pixel parent).
 */
export async function deriveMetadata(args: {
  assetBytes: Buffer;
  mimeType: string;
  active: ManifestShape | undefined;
}): Promise<DerivedMetadata> {
  return isVideoUpload(args.assetBytes, args.mimeType)
    ? deriveVideoMetadata(args.assetBytes, args.active)
    : derivePhotoMetadata(args.assetBytes, args.active);
}
