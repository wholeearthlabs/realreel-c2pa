// The uploader's declared location-privacy level, shared so the React Native
// client (the user's choice) and the Cloud Run verifier (the location-privacy
// gate) can't drift on it. "none"/"general" publish no coordinates ("general"
// adds a coarse signed label, never lat/lon); "precise" permits coordinates.

export type LocationLevel = "none" | "general" | "precise";

/** The declared levels; the isLocationLevel guard derives from this. */
export const LOCATION_LEVELS = ["none", "general", "precise"] as const;

/** Runtime guard for an untrusted value (e.g. a request field): true iff x is
 *  one of the declared levels. */
export function isLocationLevel(x: unknown): x is LocationLevel {
  return typeof x === "string" && (LOCATION_LEVELS as readonly string[]).includes(x);
}
