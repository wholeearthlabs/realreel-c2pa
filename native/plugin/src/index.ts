import { ConfigPlugin, withDangerousMod } from '@expo/config-plugins';
import * as fs from 'fs';
import * as path from 'path';

// Expo config plugin for @realreel/photo-attest.
//
// Injects the two Swift Package Manager dependencies that PhotoAttest's iOS
// code needs — c2pa-ios (product `C2PA`) and Apple's swift-certificates
// (product `X509`) — into the Podfile `post_install` on every `pod install`
// (which runs after `npx expo prebuild`). c2pa-ios is distributed exclusively
// as a Swift Package, so there is no CocoaPods path; this plugin is how a
// consumer wires it in. Apply by adding "@realreel/photo-attest" to the
// `plugins` array in app.json / app.config.js.
//
// NOTE (reference implementation): this is the Podfile/CocoaPods integration
// that ships in RealReel production today. The declarative alternative is the
// RN 0.75+ `spm_dependency` podspec helper (or cocoapods-spm's `spm_pkg`), but
// third-party SPM deps in Expo modules still hit duplicate-symbol errors on
// transitive chains like swift-crypto/swift-asn1 (expo/expo#37813 — auto-closed
// as stale, not fixed; still unresolved) — exactly what the pod-target-only
// attachment below avoids — so the plugin remains the reliable path.

const C2PA_REPOSITORY_URL = 'https://github.com/contentauth/c2pa-ios.git';
const C2PA_PRODUCT_NAME = 'C2PA';
const POD_TARGET_NAME = 'PhotoAttest';
// Sentinel inside the Podfile so re-running prebuild is idempotent.
const C2PA_PODFILE_SENTINEL = '# c2pa-ios-spm-pod-attach';

// Apple's swift-certificates: used by PhotoAttest's cert-generation path
// (ios/PhotoAttestModule.swift) — provides Certificate.PrivateKey(_ secKey:),
// which natively wraps a Secure Enclave SecKey. Pinned here (vs the C2PA.version
// sentinel) because it updates infrequently and is internal to this plugin.
//
// Deliberately an EXACT pin, whereas c2pa-ios requires swift-certificates
// `.upToNextMajor(from: "1.0.0")`. 1.19.1 is within that range, so SPM unifies
// on it today and the exact pin is a conservative, reproducible choice. If a
// future c2pa-ios bump needs a swift-certificates that 1.19.1 can't satisfy,
// relax this to a range matching upstream rather than letting the two diverge.
const SWIFT_CERT_REPOSITORY_URL = 'https://github.com/apple/swift-certificates.git';
const SWIFT_CERT_PRODUCT_NAME = 'X509';
const SWIFT_CERT_VERSION = '1.19.1';
const SWIFT_CERT_PODFILE_SENTINEL = '# swift-certificates-spm-pod-attach';

// The c2pa-ios version is the single source of truth shipped with this package
// at ios/C2PA.version. The compiled plugin lives at <pkg>/plugin/build/index.js,
// so the sentinel is two directories up.
//
// This is the one value here read from a file and hand-edited (see the README's
// "Updating the C2PA version") rather than a trusted in-source literal, and it
// gets interpolated into the install-time Ruby below (buildAttachSnippet's
// `'version' => '...'`). Validate it as a strict version so a stray quote or
// newline from a typo/bad merge fails the prebuild loudly instead of injecting
// executable Ruby that would run on every consumer's `pod install`.
function readC2paVersion(): string {
  const sentinel = path.join(__dirname, '..', '..', 'ios', 'C2PA.version');
  const version = fs.readFileSync(sentinel, 'utf8').trim();
  if (!/^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(
      `[@realreel/photo-attest] ios/C2PA.version is not a valid version: ${JSON.stringify(version)}`
    );
  }
  return version;
}

// We attach each SPM product to ONLY the PhotoAttest pod target, not the app
// target. Attaching to both produced ~14k duplicate-symbol linker errors
// (C2PA + swift-crypto + swift-asn1 + swift-certificates + CCryptoBoringSSL):
// with `s.static_framework` pods, libPhotoAttest.a lipos in every transitive
// Swift symbol it imports, so a second app-target SPM link double-counts them.
// Pod-only keeps all C2PA symbols inside libPhotoAttest.a; the app inherits
// them transitively. The pod's `pod_target_xcconfig` (see PhotoAttest.podspec)
// extends the Swift import paths so compile-time module resolution still works.
function buildAttachSnippet(opts: {
  sentinel: string;
  lambdaName: string;
  repo: string;
  product: string;
  version: string;
}): string {
  return `
  ${opts.sentinel} (managed by @realreel/photo-attest)
  # Attaches the ${opts.product} SPM product to the ${POD_TARGET_NAME} pod target
  # so \`import ${opts.product}\` resolves during pod compilation. Without this,
  # only the app target sees the SPM dep and the pod's Swift compile fails.
  ${opts.lambdaName} = lambda do |installer|
    pkg_class = Xcodeproj::Project::Object::XCRemoteSwiftPackageReference
    prod_class = Xcodeproj::Project::Object::XCSwiftPackageProductDependency
    repo = '${opts.repo}'
    product = '${opts.product}'
    pods_project = installer.pods_project

    target = pods_project.targets.find { |t| t.name == '${POD_TARGET_NAME}' }
    next unless target

    package_ref = pods_project.root_object.package_references.find do |r|
      r.is_a?(pkg_class) && r.repositoryURL == repo
    end
    unless package_ref
      package_ref = pods_project.new(pkg_class)
      package_ref.repositoryURL = repo
      package_ref.requirement = { 'kind' => 'exactVersion', 'version' => '${opts.version}' }
      pods_project.root_object.package_references << package_ref
    end

    already_attached = (target.package_product_dependencies || []).any? do |d|
      d.product_name == product
    end
    unless already_attached
      product_dep = pods_project.new(prod_class)
      product_dep.package = package_ref
      product_dep.product_name = product
      target.package_product_dependencies ||= []
      target.package_product_dependencies << product_dep
    end

    pods_project.save
  end
  ${opts.lambdaName}.call(installer)
`;
}

// Inserts the SPM-attach snippets inside the existing `post_install do |installer|`
// block that Expo's generated Podfile already contains (for
// react_native_post_install). We inject AFTER that call so our fixups run after
// RN's. Each snippet is independently idempotent via its own sentinel string.
function injectIntoPodfile(podfilePath: string, c2paVersion: string): void {
  let podfile = fs.readFileSync(podfilePath, 'utf8');

  const snippets: string[] = [];
  if (!podfile.includes(C2PA_PODFILE_SENTINEL)) {
    snippets.push(
      buildAttachSnippet({
        sentinel: C2PA_PODFILE_SENTINEL,
        lambdaName: 'c2pa_attach',
        repo: C2PA_REPOSITORY_URL,
        product: C2PA_PRODUCT_NAME,
        version: c2paVersion,
      })
    );
  }
  if (!podfile.includes(SWIFT_CERT_PODFILE_SENTINEL)) {
    snippets.push(
      buildAttachSnippet({
        sentinel: SWIFT_CERT_PODFILE_SENTINEL,
        lambdaName: 'swift_certificates_attach',
        repo: SWIFT_CERT_REPOSITORY_URL,
        product: SWIFT_CERT_PRODUCT_NAME,
        version: SWIFT_CERT_VERSION,
      })
    );
  }
  if (snippets.length === 0) {
    return; // both already injected
  }

  const marker = /(react_native_post_install\([\s\S]*?\)\n)/;
  if (!marker.test(podfile)) {
    throw new Error(
      '[@realreel/photo-attest] Could not find react_native_post_install(...) in the ' +
        'Podfile to anchor the SPM injection. Is this an Expo-generated iOS project?'
    );
  }
  podfile = podfile.replace(marker, `$1${snippets.join('')}`);
  fs.writeFileSync(podfilePath, podfile, 'utf8');
}

const withC2PAiOS: ConfigPlugin = (config) => {
  return withDangerousMod(config, [
    'ios',
    (cfg) => {
      const podfilePath = path.join(cfg.modRequest.platformProjectRoot, 'Podfile');
      injectIntoPodfile(podfilePath, readC2paVersion());
      return cfg;
    },
  ]);
};

export default withC2PAiOS;
