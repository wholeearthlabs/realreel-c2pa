Pod::Spec.new do |s|
  s.name           = 'PhotoAttest'
  s.version        = '1.0.0'
  s.summary        = 'Hardware-backed photo signing key + App Attest for RealReel'
  s.description    = s.summary
  s.license        = 'MIT'
  s.author         = 'RealReel'
  s.homepage       = 'https://github.com/wholeearthlabs/realreel-c2pa'
  s.platform       = :ios, '16.0'
  s.swift_version  = '5.4'
  s.source         = { git: 'https://github.com/wholeearthlabs/realreel-c2pa' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.frameworks = 'Security', 'CryptoKit', 'DeviceCheck', 'ImageIO', 'AVFoundation', 'UIKit'

  # SPM-in-pod plumbing for SPM dependencies (c2pa-ios + swift-certificates):
  #
  # The post_install hook in plugins/withC2PAiOS.js attaches both c2pa-ios
  # (product `C2PA`) and swift-certificates (product `X509`) as
  # packageProductDependencies on this pod target in Pods.xcodeproj — that
  # gives us the build-order edge (their .swiftmodules are built before this
  # pod) and a link-time dependency on each Swift product.
  #
  # But CocoaPods uses **per-target product dirs**: this pod's
  # ${BUILT_PRODUCTS_DIR} resolves to ".../Build/Products/Debug-iphonesimulator/
  # PhotoAttest/", while SPM places the .swiftmodules (C2PA, X509, swift-asn1,
  # swift-crypto, etc.) one level up at ".../Debug-iphonesimulator/". Without
  # an explicit search path the Swift compiler invocation for this pod can't
  # see those modules even though they physically exist. Adding the parent dir
  # to SWIFT_INCLUDE_PATHS + FRAMEWORK_SEARCH_PATHS closes the gap for ALL
  # SPM products attached to this pod target. (CONFIGURATION_BUILD_DIR is the
  # same as BUILT_PRODUCTS_DIR for pods; both point at the per-target subdir.)
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule',
    'SWIFT_INCLUDE_PATHS' => '$(inherited) "${BUILT_PRODUCTS_DIR}/.."',
    'FRAMEWORK_SEARCH_PATHS' => '$(inherited) "${BUILT_PRODUCTS_DIR}/.."'
  }

  s.source_files = "**/*.{h,m,swift}"
end
