---
"@realreel/photo-attest": patch
---

Fix iOS production archive failing with `"C2PAC.xcframework-ios.signature" couldn't be copied to "Signatures" because an item with the same name already exists`.

The config plugin now adds an app-target build phase that deletes the duplicate xcframework signature before Xcode's archive packaging step, working around the long-standing SwiftPM `binaryTarget` archive bug (Xcode 15+, still present on Xcode 26). The plugin's existing Podfile SPM injection is unchanged; the new build phase is idempotent and a no-op on non-archive builds.
