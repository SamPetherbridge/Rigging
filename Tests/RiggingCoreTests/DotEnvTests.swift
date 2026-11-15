import Foundation
import RiggingCore
import RiggingTesting
import Testing

@Suite("DotEnvParser & DotEnvSource")
struct DotEnvTests {

    @Test("Comments, export prefix, single/double/unquoted strings, and escape sequences")
    func commentsExportQuotesAndEscapes() throws {
        let content = #"""
            # Leading full-line comment
              # Indented comment
            export EXPORTED_KEY = "exported-value"
            UNQUOTED=plain_value # trailing inline comment
            UNQUOTED_HASH=color#ff00aa
            EMPTY_WITH_COMMENT= # inline comment on empty value
            SINGLE_QUOTED='literal \n ${EXPORTED_KEY} # not a comment'
            DOUBLE_QUOTED="line1\nline2\t\"quoted\"\\slash\$literal"
            """#

        let entries = try DotEnvParser.parse(content)
        let byKey = Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0) })

        #expect(byKey["EXPORTED_KEY"]?.value == "exported-value")
        #expect(byKey["EXPORTED_KEY"]?.line == 3)

        #expect(byKey["UNQUOTED"]?.value == "plain_value")
        #expect(byKey["UNQUOTED"]?.line == 4)

        // '#' without preceding whitespace is preserved in unquoted values
        #expect(byKey["UNQUOTED_HASH"]?.value == "color#ff00aa")
        #expect(byKey["EMPTY_WITH_COMMENT"]?.value == "")

        // Single-quoted strings do not expand escapes or ${...}
        #expect(byKey["SINGLE_QUOTED"]?.value == #"literal \n ${EXPORTED_KEY} # not a comment"#)

        // Double-quoted strings expand \n, \t, \", \\, \$
        #expect(byKey["DOUBLE_QUOTED"]?.value == "line1\nline2\t\"quoted\"\\slash$literal")
    }

    @Test("Multiline PEM blocks (both double-quoted and unquoted) preserve exact 1-based line numbers")
    func multilinePEMBlocksAndLineNumbers() throws {
        let content = """
            # Line 1
            QUOTED_KEY="-----BEGIN PRIVATE KEY-----
            LINE_A_PAYLOAD
            LINE_B_PAYLOAD
            -----END PRIVATE KEY-----"
            AFTER_QUOTED=ok
            UNQUOTED_KEY=-----BEGIN PRIVATE KEY-----
            UNQUOTED_LINE_A
            UNQUOTED_LINE_B
            -----END PRIVATE KEY-----
            FINAL_VAR=done
            """

        let entries = try DotEnvParser.parse(content)
        let byKey = Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0) })

        #expect(byKey["QUOTED_KEY"]?.line == 2)
        #expect(
            byKey["QUOTED_KEY"]?.value == """
                -----BEGIN PRIVATE KEY-----
                LINE_A_PAYLOAD
                LINE_B_PAYLOAD
                -----END PRIVATE KEY-----
                """
        )

        #expect(byKey["AFTER_QUOTED"]?.line == 6)
        #expect(byKey["AFTER_QUOTED"]?.value == "ok")

        #expect(byKey["UNQUOTED_KEY"]?.line == 7)
        #expect(
            byKey["UNQUOTED_KEY"]?.value == """
                -----BEGIN PRIVATE KEY-----
                UNQUOTED_LINE_A
                UNQUOTED_LINE_B
                -----END PRIVATE KEY-----
                """
        )

        #expect(byKey["FINAL_VAR"]?.line == 11)
        #expect(byKey["FINAL_VAR"]?.value == "done")
    }

    @Test("Variable interpolation: ${VAR}, ${VAR:-default}, ${VAR-default}, with process env beating .env")
    func variableInterpolationAndEnvPrecedence() throws {
        let content = #"""
            HOST=dotenv.example.com
            EMPTY_LOCAL=""
            URL="https://${HOST}/v1"
            PORT="${PORT:-8443}"
            FALLBACK_WHEN_EMPTY="${EMPTY_LOCAL:-fallback_nonempty}"
            KEEP_EMPTY_WITHOUT_COLON="${EMPTY_LOCAL-should_not_use}"
            UNSET_WITHOUT_COLON="${TOTALLY_UNSET-unset_default}"
            """#

        // Process environment HOST overrides HOST defined inside .env during interpolation
        let entries = try DotEnvParser.parse(
            content,
            environment: ["HOST": "env.example.com"]
        )
        let byKey = Dictionary(uniqueKeysWithValues: entries.map { ($0.key, $0.value) })

        #expect(byKey["URL"] == "https://env.example.com/v1")
        #expect(byKey["PORT"] == "8443")
        #expect(byKey["FALLBACK_WHEN_EMPTY"] == "fallback_nonempty")
        #expect(byKey["KEEP_EMPTY_WITHOUT_COLON"] == "")
        #expect(byKey["UNSET_WITHOUT_COLON"] == "unset_default")
    }

    @Test("Multi-file .env + .env.local override cascade and 1-based .dotEnv origin tracking")
    func multiFileDotEnvCascadeAndLineProvenance() async throws {
        let config = SettingsConfiguration(
            envPrefix: "ASC_",
            dotEnvFiles: [".env", ".env.local"]
        )
        let context = SettingsContext.inMemory(
            environment: ["ASC_REGION": "us-east-1"],
            files: [
                "/repo/.env": """
                    # Base .env
                    ASC_APP_ID=1000000001
                    ASC_TIMEOUT=30s
                    ASC_BASE_URL=https://base.example.com
                    """,
                "/repo/.env.local": """
                    # Local overrides (line 1)
                    # Line 2 comment
                    ASC_APP_ID=2000000002
                    ASC_ENDPOINT=${ASC_BASE_URL}/${ASC_REGION}
                    """,
            ]
        )

        let tree = try await DotEnvSource().load(configuration: config, context: context)

        let appIdNode = try #require(tree.lookup(path: ["appId"]))
        #expect(appIdNode.value == .string("2000000002"))
        #expect(appIdNode.origin == .dotEnv(path: "/repo/.env.local", line: 3, variable: "ASC_APP_ID"))
        #expect(appIdNode.overriddenOrigins == [.dotEnv(path: "/repo/.env", line: 2, variable: "ASC_APP_ID")])

        let timeoutNode = try #require(tree.lookup(path: ["timeout"]))
        #expect(timeoutNode.value == .string("30s"))
        #expect(timeoutNode.origin == .dotEnv(path: "/repo/.env", line: 3, variable: "ASC_TIMEOUT"))

        // Cross-file interpolation uses earlier .env's ASC_BASE_URL + process env's ASC_REGION
        let endpointNode = try #require(tree.lookup(path: ["endpoint"]))
        #expect(endpointNode.value == .string("https://base.example.com/us-east-1"))
        #expect(endpointNode.origin == .dotEnv(path: "/repo/.env.local", line: 4, variable: "ASC_ENDPOINT"))
    }

    @Test("Syntax error diagnostics report accurate 1-based line numbers")
    func syntaxErrorsReportLineNumbers() {
        let unterminatedSingle = "VALID=1\nBROKEN='unterminated"
        let err1 = #expect(throws: DotEnvParseError.self) {
            try DotEnvParser.parse(unterminatedSingle, path: "/repo/.env")
        }
        #expect(err1?.line == 2)
        #expect(err1?.path == "/repo/.env")

        let strictNoEquals = "# comment\nNOT_AN_ASSIGNMENT\n"
        let err2 = #expect(throws: DotEnvParseError.self) {
            try DotEnvParser.parse(strictNoEquals, strict: true)
        }
        #expect(err2?.line == 2)

        let unterminatedPEM = "KEY=-----BEGIN PRIVATE KEY-----\nBODY_WITHOUT_END"
        let err3 = #expect(throws: DotEnvParseError.self) {
            try DotEnvParser.parse(unterminatedPEM)
        }
        #expect(err3?.line == 1)
    }
}
