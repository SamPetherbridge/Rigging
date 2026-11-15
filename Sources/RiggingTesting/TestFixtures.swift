import Foundation

/// Deterministic, synthetic fixtures for unit and integration tests across Rigging modules.
///
/// All keys, identifiers, and endpoints in ``TestFixtures`` are synthetic test values safe to use
/// in open-source test suites without touching real credentials or services.
public enum TestFixtures: Sendable {
    /// Synthetic PKCS#8 EC private key PEM block suitable for testing multiline `.env` parsing,
    /// `SecretTransform.normalizePEM`, `DiagnosticRedactor` line scrubbing, and `withEphemeralFile`.
    public static let sampleP8PEM: String = """
        -----BEGIN PRIVATE KEY-----
        MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg7xSyntheticTestK
        eyMaterialForRiggingUnitTests0123456789abcdefABCgYIKoZIzj0DAQehA
        RANCAATestPublicKeyPayloadForRiggingVerificationSuite9876543210X
        YZabcdefghijklmnopqrstuvwxyz012345==
        -----END PRIVATE KEY-----
        """

    /// Single-line `\n`-escaped variant of ``sampleP8PEM`` as commonly stored in CI environment variables.
    public static var sampleEscapedP8PEM: String {
        sampleP8PEM.replacingOccurrences(of: "\n", with: "\\n")
    }

    /// Standard Base64 encoding of ``sampleP8PEM``.
    public static var sampleBase64P8PEM: String {
        Data(sampleP8PEM.utf8).base64EncodedString()
    }

    /// `"base64:"`-prefixed Base64 encoding of ``sampleP8PEM`` for testing `SecretTransform.decodeBase64IfPrefixed`.
    public static var samplePrefixedBase64P8PEM: String {
        "base64:\(sampleBase64P8PEM)"
    }

    /// Sample `.asc.json` project configuration referencing `op://` secrets with a named `"staging"` profile.
    public static let sampleASCProjectJSON: String = #"""
        {
          "$schema": "https://schemas.example.com/asc.schema.json",
          "auth": {
            "keyId": "op://Eng/ASC/key_id",
            "issuerId": "11111111-2222-3333-4444-555555555555",
            "privateKey": "op://Eng/ASC/private_key"
          },
          "appId": "6500000001",
          "readOnly": false,
          "profiles": {
            "staging": {
              "appId": "6500000099",
              "readOnly": true
            }
          }
        }
        """#

    /// Sample `.env` file exercising comments, `export`, single/double quotes, `${VAR:-default}` expansion, and multiline PEMs.
    public static let sampleDotEnv: String = #"""
        # Sample .env fixture for Rigging tests
        export ASC_KEY_ID="ABC1234567"
        ASC_APP_ID=6500000001 # inline comment
        ASC_LITERAL='${NOT_EXPANDED}'
        ASC_ENDPOINT="https://${ASC_HOST:-api.appstoreconnect.apple.com}/v1"
        ASC_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
        MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg7xSyntheticTestK
        eyMaterialForRiggingUnitTests0123456789abcdefABCgYIKoZIzj0DAQehA
        RANCAATestPublicKeyPayloadForRiggingVerificationSuite9876543210X
        YZabcdefghijklmnopqrstuvwxyz012345==
        -----END PRIVATE KEY-----"
        """#
}
