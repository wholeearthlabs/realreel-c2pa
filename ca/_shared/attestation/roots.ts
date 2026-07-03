// Trusted root certificates for platform attestation chain validation.
//
// These are embedded as PEM strings (committed to the repo) rather than
// fetched at runtime — the roots rotate on the order of years, and we want
// the verification logic to be hermetic and offline.
//
// **Defense in depth**: each PEM has an expected SHA-256 fingerprint listed
// alongside it. The validators (apple.ts, android.ts) call
// `assertRootFingerprints()` at first-parse, which throws if any embedded
// PEM no longer hashes to the expected value. This catches the "future
// formatter accidentally re-wraps a PEM body and silently breaks
// verification" failure mode.
//
// To re-derive a fingerprint manually after fetching from the source:
//
//   openssl x509 -in <(echo "$PEM") -noout -fingerprint -sha256
//
// Apple App Attestation Root CA — published at:
//   https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
export const APPLE_APPATTEST_ROOT_PEM = `\
-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`;

// Google Hardware Attestation Roots — the self-signed roots that real-device
// attestation chains terminate at. Google publishes the authoritative current
// set at https://android.googleapis.com/attestation/root (a JSON array of
// PEMs); cross-check against that endpoint when a CHAIN_INVALID spike
// suggests a rotation we haven't picked up.
//
// Google has rotated these in the past and may again — when they do, add the
// new root to this array; do not remove old ones until the corresponding
// device population is fully retired, EXCEPT when the rotation is a re-issue
// of the same subject+key with a fresh validity window (see Root #2): then
// REPLACE the expired cert, because pkijs can pick the expired anchor's path
// over the fresh one and reject chains that should validate.
//
// Root #1 — serialNumber=e35d38c6897d47e8 (RSA 4096, EC-issued strongbox + tee chains)
//   SHA-256: 19:DE:1C:3E:1D:A7:E0:6F:3C:27:12:30:13:42:C1:79:41:B1:EC:90:BA:5E:E3:96:A8:EC:2E:E4:F4:6D:FA:D2
//   Valid:   2018-03-21 → 2028-03-18
//
// Root #2 — serialNumber=f92009e853b6b045 (RSA 4096), 2022 RE-ISSUE
//   SHA-256: CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC
//   Valid:   2022-03-20 → 2042-03-15 (cert serial f1c172a699eaf51d)
//   Same subject + same RSA key as the ORIGINAL 2016 self-signed cert
//   (cert serial e8fa196314d2fa18), which expired 2026-05-24 and briefly
//   took down enrollment for devices anchored at this key. Google publishes
//   this re-issue at https://android.googleapis.com/attestation/root; device
//   chains still present the old expired self-signed cert as their top
//   element, but path building matches the trust anchor by subject/key, so
//   they validate against this one. Do NOT keep the expired original
//   alongside: pkijs may pick the expired anchor's path and reject a chain
//   the fresh anchor would accept.
//
// Root #3 — CN="Key Attestation CA1", O="Google LLC" (ECDSA P-384, deployed July 2025)
//   SHA-256: 6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0
//   Valid:   2025-07-17 → 2035-07-15
//   Used by: modern devices using Android's next-gen attestation hierarchy.
//            Verified live against a real StrongBox-equipped device (Pixel/Galaxy
//            class) in May 2026 — chain terminates here.
export const GOOGLE_HW_ATTESTATION_ROOT_PEMS: string[] = [
  // Root #1 — e35d38c6897d47e8
  `\
-----BEGIN CERTIFICATE-----
MIIFXzCCA0egAwIBAgIINQWgov3MUeQwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE
BRMQZTM1ZDM4YzY4OTdkNDdlODAeFw0xODAzMjEwMzU1MDFaFw0yODAzMTgwMzU1
MDFaMBsxGTAXBgNVBAUTEGUzNWQzOGM2ODk3ZDQ3ZTgwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCoQi070/6PH9BAuJiBcTp8j5R2/Fj6kXFaSxsvUjJK
Rdi/FCOwUFBJfyhHiWJhga2iguIjAJuhZx5XlMj0pSY7buJisPqFknZhKdvfoi4C
54j54D+XxCky1APVjD5uc203H+hrRlhh6x4/LTzSXWvb0YLjfOK07HvSddSRCyKn
PydI5bhyCb5QMtVKHzC4Axgx+BihwG1B4UQjOpZpXBHIFZ6EK/XBFeJX0tgrx0MC
czkc1X0OhNFKAYumCKcKyh4q2cGh7UwTRJIT4beIJVrOKDVwo3Fc50k3ICpOAc1z
RGzRwupIKKGtW455KW1OIyAtTJ4NqfIwrkQy5EJ9w/zDzjqFiDNdgTXaMtsz52jH
UndfO3lzfvVdBjt2FWLRkWrFmd1tjQ6LQQFPrSvUHo0XN5kIiOYdNlAyIwBZ51Zn
/clU9he78UYAmXHdjfh04DXWgf+GGIFFdmg9tbiHwdqi8yEcakKHL2TYNylmFJuK
OkvLIS5iqEMu29OQyv+BJ1NNQtyn8o1D5f3K2a5qyoUcrL0Je2w28ByL1JeFURO7
wbzkXx9FWwH0stCs/dYq4JKJ8GxKN8aBOl/51atA1cdZAyI55B9ueAYwPevteORG
DhEfcKRaGiWJpSzIFLDmbL9uSpCAw5uqx5h1IRAX1OLi56EsVaFUedt8IqUaCkUc
MQIDAQABo4GmMIGjMB0GA1UdDgQWBBRTDkUbExXTrVzqjui8W7YUis0d6DAfBgNV
HSMEGDAWgBRTDkUbExXTrVzqjui8W7YUis0d6DAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwICBDBABgNVHR8EOTA3MDWgM6Axhi9odHRwczovL2FuZHJvaWQu
Z29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzANBgkqhkiG9w0BAQsFAAOC
AgEACHPElcXZEY6jItn3SnVn6gdOCvuFIrhB4J4fhxa6OlDCbxsylHHAbpyoOSJD
0R5dIBTRvz49ElfCpI9yp4l5tUOjWj2K3tMfQjhKN277jApdxbZ6MNac2u+Z3dwS
+34YiiCJLVKhVzWanXk/+9rmVnBzm7qvgan90j2SmH1oYIA3GowJL+1OWSjj6cBH
1VrU7guVd7q+aCEQPhTesfbmUkdUbM/TjUMyhf5SZ7WB8A28MnyYQcFttmGDsE1H
Zx4fTz8iXxjaph33alasmFUWGtG7KyzvbYUwwUOmpPd32eT8ocx3B0Z3g+Vo2Cv2
LzRRNp15FOf/Ag5HWloyIv3xrsBA2fa4xzOm3/t1Aq0ZViXLLerKKmU/EJKo7t5g
E0wtNebicNhUJaX2C+vShjfleBBwhs33a8b7dBFX/JMwU5+09N83WHRPZjCrYuK3
Uu4qANfJ+f1k+weqh6MpRxAZ6TT0OQt1XQz7rDAlq7AopfXRXI74OCNJf8d+2CPN
VW8i5IHNFjvyEz8ms1ETdw5n3uRbYIgYuCV2Pud3MCwaMTv2E0dLAqg8uJo0JYlh
H7wbqidMm2ODRL5FaqWbb2pfW0vbpCyGfyw0RQGTJAE7xVdvzfdun9HATDm6TbJF
cejBdJImfwpZmDOBtDPIbsg5+QVE3lLF6Licq13i5tIg5yQ=
-----END CERTIFICATE-----
`,
  // Root #2 — f92009e853b6b045 (2022 re-issue, serial f1c172a699eaf51d)
  `\
-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----
`,
  // Root #3 — Key Attestation CA1 (ECDSA P-384, valid 2025-07-17 → 2035-07-15)
  `\
-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----
`,
];

// === Fingerprint pinning ===
//
// Each embedded root's expected SHA-256 fingerprint of the DER body. Any
// formatter accident or accidental edit that re-wraps PEM bodies will be
// caught at module-load time when this top-level await runs (Deno + the
// Supabase Edge Runtime support top-level await; the function will fail to
// start with a clear error rather than silently rejecting valid attestations).
//
// Fingerprints normalised: hex, uppercase, no separators. Re-derive via:
//   openssl x509 -in <(echo "$PEM") -noout -fingerprint -sha256 | tr -d ':' | tr a-f A-F
const EXPECTED_FINGERPRINTS: Array<
  { name: string; pem: string; fingerprint: string }
> = [
  {
    name: "Apple App Attestation Root CA",
    pem: APPLE_APPATTEST_ROOT_PEM,
    fingerprint:
      "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932",
  },
  {
    name: "Google HW Attestation Root #1 (e35d38c6897d47e8)",
    pem: GOOGLE_HW_ATTESTATION_ROOT_PEMS[0],
    fingerprint:
      "19DE1C3E1DA7E06F3C2712301342C17941B1EC90BA5EE396A8EC2EE4F46DFAD2",
  },
  {
    name: "Google HW Attestation Root #2 (f92009e853b6b045, 2022 re-issue)",
    pem: GOOGLE_HW_ATTESTATION_ROOT_PEMS[1],
    fingerprint:
      "CEDB1CB6DC896AE5EC797348BCE9286753C2B38EE71CE0FBE34A9A1248800DFC",
  },
  {
    name: "Google HW Attestation Root #3 (Key Attestation CA1)",
    pem: GOOGLE_HW_ATTESTATION_ROOT_PEMS[2],
    fingerprint:
      "6D9DB4CE6C5C0B293166D08986E05774A8776CEB525D9E4329520DE12BA4BCC0",
  },
];

async function sha256HexOfPemDer(pem: string): Promise<string> {
  const stripped = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(stripped);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  const hashBuf = await crypto.subtle.digest("SHA-256", der as BufferSource);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join("");
}

// Verify all fingerprints at module-load. Top-level await runs once when this
// module is first imported — fails the whole edge function with a clear error
// if any embedded PEM has been corrupted.
for (const root of EXPECTED_FINGERPRINTS) {
  const actual = await sha256HexOfPemDer(root.pem);
  if (actual !== root.fingerprint) {
    throw new Error(
      `Embedded root cert "${root.name}" fingerprint mismatch.\n` +
        `  expected: ${root.fingerprint}\n` +
        `  actual:   ${actual}\n` +
        "The PEM body in roots.ts may have been corrupted by a formatter or accidental edit.",
    );
  }
}
