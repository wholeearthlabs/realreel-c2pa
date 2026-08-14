// Byte-level container sniff shared by the verify() mimeType gate and
// derive-metadata's photo-vs-video pick, so the two can never disagree
// about what a file is.

export type ContainerKind = "jpeg" | "isobmff" | "unknown";

export function sniffContainer(bytes: Buffer): ContainerKind {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return "jpeg";
  }
  if (bytes.length >= 12 && bytes.toString("latin1", 4, 8) === "ftyp") {
    return "isobmff";
  }
  return "unknown";
}
