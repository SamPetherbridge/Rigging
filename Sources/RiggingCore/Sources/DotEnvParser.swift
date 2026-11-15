import Foundation

/// A key-value assignment parsed from a `.env` file together with its 1-based starting line number.
public struct DotEnvEntry: Sendable, Equatable, Hashable {
    /// Trimmed variable identifier before `=`.
    public let key: String

    /// Resolved string value after quote unescaping and optional `${...}` variable expansion.
    public let value: String

    /// One-based line number where this assignment began in the `.env` file.
    public let line: Int

    /// Creates a parsed `.env` entry.
    ///
    /// - Parameters:
    ///   - key: Variable identifier.
    ///   - value: Resolved string value.
    ///   - line: One-based line number in the `.env` document.
    public init(key: String, value: String, line: Int) {
        self.key = key
        self.value = value
        self.line = line
    }
}

/// An error thrown when `.env` content contains malformed quotes, escapes, or variable interpolations.
public struct DotEnvParseError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    /// Optional `.env` file path associated with the parse failure.
    public let path: String?

    /// One-based line number where the syntax error started.
    public let line: Int

    /// Human-readable description of the syntax error.
    public let message: String

    /// Creates a `.env` syntax error with file and line context.
    ///
    /// - Parameters:
    ///   - path: Optional path to the `.env` file being parsed.
    ///   - line: One-based line number where parsing failed.
    ///   - message: Diagnostic explanation of the syntax error.
    public init(path: String? = nil, line: Int, message: String) {
        self.path = path
        self.line = line
        self.message = message
    }

    /// Formatted `<path>:<line>: <message>` diagnostic string.
    public var description: String {
        if let path {
            return "\(path):\(line): \(message)"
        }
        return "line \(line): \(message)"
    }

    /// Localized error description matching ``description`` for CLI error reporters.
    public var errorDescription: String? {
        description
    }
}

/// Pure-Swift `.env` parser supporting comments, `export` prefixes, quoted and multiline strings,
/// unquoted PEM blocks, escape sequences, and `${VAR}` / `${VAR:-default}` / `${VAR-default}` expansion.
///
/// ```swift
/// let entries = try DotEnvParser.parse("""
/// export API_HOST="api.example.com"
/// API_URL="https://${API_HOST}/v1"
/// """)
/// ```
public enum DotEnvParser: Sendable {
    /// Parses UTF-8 `.env` bytes into ordered ``DotEnvEntry`` values with 1-based line numbers.
    ///
    /// - Parameters:
    ///   - data: Raw UTF-8 `.env` file bytes.
    ///   - environment: Process environment dictionary consulted first during `${...}` interpolation.
    ///   - existingEntries: Previously parsed `.env` entries consulted second during `${...}` interpolation.
    ///   - expandVariables: Whether `${VAR}`, `${VAR:-default}`, and `${VAR-default}` expressions are expanded.
    ///   - strict: When `true`, lines without `=` or unexpected trailing characters after quotes throw ``DotEnvParseError``.
    ///   - path: Optional file path attached to thrown ``DotEnvParseError`` diagnostics.
    /// - Returns: Ordered ``DotEnvEntry`` items in file order.
    /// - Throws: ``DotEnvParseError`` when the data is not valid UTF-8 or contains malformed `.env` syntax.
    public static func parse(
        data: Data,
        environment: [String: String] = [:],
        existingEntries: [String: String] = [:],
        expandVariables: Bool = true,
        strict: Bool = false,
        path: String? = nil
    ) throws -> [DotEnvEntry] {
        guard let content = String(data: data, encoding: .utf8) else {
            throw DotEnvParseError(path: path, line: 1, message: "Invalid UTF-8 encoding in .env file")
        }
        return try parse(
            content,
            environment: environment,
            existingEntries: existingEntries,
            expandVariables: expandVariables,
            strict: strict,
            path: path
        )
    }

    /// Parses `.env` text into ordered ``DotEnvEntry`` values with 1-based line numbers.
    ///
    /// - Parameters:
    ///   - content: Raw `.env` text content.
    ///   - environment: Process environment dictionary consulted first during `${...}` interpolation.
    ///   - existingEntries: Previously parsed `.env` entries consulted second during `${...}` interpolation.
    ///   - expandVariables: Whether `${VAR}`, `${VAR:-default}`, and `${VAR-default}` expressions are expanded.
    ///   - strict: When `true`, lines without `=` or unexpected trailing characters after quotes throw ``DotEnvParseError``.
    ///   - path: Optional file path attached to thrown ``DotEnvParseError`` diagnostics.
    /// - Returns: Ordered ``DotEnvEntry`` items in file order.
    /// - Throws: ``DotEnvParseError`` when malformed quotes, escapes, or interpolations are encountered.
    public static func parse(
        _ content: String,
        environment: [String: String] = [:],
        existingEntries: [String: String] = [:],
        expandVariables: Bool = true,
        strict: Bool = false,
        path: String? = nil
    ) throws -> [DotEnvEntry] {
        var stripped = content
        if stripped.hasPrefix("\u{FEFF}") {
            stripped.removeFirst()
        }
        // Normalize CRLF and standalone CR to LF so every newline is a single '\n' Character
        // and 1-based line numbers remain exact.
        let normalized = stripped
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")

        let chars = Array(normalized)
        let count = chars.count
        var index = 0
        var currentLine = 1

        var entries: [DotEnvEntry] = []
        var localEnv = existingEntries

        func isHorizontalWhitespace(_ ch: Character) -> Bool {
            ch == " " || ch == "\t"
        }

        func skipHorizontalWhitespace() -> Bool {
            var skipped = false
            while index < count && isHorizontalWhitespace(chars[index]) {
                index += 1
                skipped = true
            }
            return skipped
        }

        func skipRestOfLine() {
            while index < count && chars[index] != "\n" {
                index += 1
            }
        }

        func lookupVariable(_ name: String) -> String? {
            if let envVal = environment[name] {
                return envVal
            }
            return localEnv[name]
        }

        while index < count {
            _ = skipHorizontalWhitespace()

            if index >= count {
                break
            }

            let ch = chars[index]
            if ch == "\n" {
                index += 1
                currentLine += 1
                continue
            }

            if ch == "#" {
                skipRestOfLine()
                continue
            }

            let entryLine = currentLine

            // Optional `export` prefix followed by horizontal whitespace
            if index + 6 < count,
               chars[index] == "e",
               chars[index + 1] == "x",
               chars[index + 2] == "p",
               chars[index + 3] == "o",
               chars[index + 4] == "r",
               chars[index + 5] == "t",
               isHorizontalWhitespace(chars[index + 6]) {
                index += 6
                _ = skipHorizontalWhitespace()
            }

            // Read key up to '=' or '\n'
            let keyStart = index
            var foundEquals = false
            while index < count {
                let c = chars[index]
                if c == "=" {
                    foundEquals = true
                    break
                }
                if c == "\n" {
                    break
                }
                index += 1
            }

            if !foundEquals {
                let rawLine = String(chars[keyStart..<index]).trimmingCharacters(in: .whitespaces)
                if strict && !rawLine.isEmpty && !rawLine.hasPrefix("#") {
                    throw DotEnvParseError(
                        path: path,
                        line: entryLine,
                        message: "Expected '=' in .env assignment"
                    )
                }
                skipRestOfLine()
                continue
            }

            var rawKey = String(chars[keyStart..<index]).trimmingCharacters(in: .whitespaces)
            if rawKey.count >= 2,
               (rawKey.first == "\"" && rawKey.last == "\"") || (rawKey.first == "'" && rawKey.last == "'") {
                rawKey.removeFirst()
                rawKey.removeLast()
                rawKey = rawKey.trimmingCharacters(in: .whitespaces)
            }

            guard !rawKey.isEmpty else {
                throw DotEnvParseError(
                    path: path,
                    line: entryLine,
                    message: "Empty variable name before '='"
                )
            }

            if rawKey.contains("\0") {
                throw DotEnvParseError(
                    path: path,
                    line: entryLine,
                    message: "Variable name contains invalid NUL byte"
                )
            }

            // Consume '='
            index += 1

            let hadLeadingSpace = skipHorizontalWhitespace()

            // Empty value at EOL, EOF, or inline comment after whitespace (`FOO= # comment`)
            if index >= count || chars[index] == "\n" {
                entries.append(DotEnvEntry(key: rawKey, value: "", line: entryLine))
                localEnv[rawKey] = ""
                continue
            }

            if hadLeadingSpace && chars[index] == "#" {
                skipRestOfLine()
                entries.append(DotEnvEntry(key: rawKey, value: "", line: entryLine))
                localEnv[rawKey] = ""
                continue
            }

            let quoteChar = chars[index]
            let parsedValue: String

            if quoteChar == "'" {
                // Single-quoted literal value: no escapes, no interpolation, multiline supported
                index += 1
                var buffer = String()
                var closed = false

                while index < count {
                    let c = chars[index]
                    index += 1
                    if c == "'" {
                        closed = true
                        break
                    }
                    if c == "\n" {
                        currentLine += 1
                    }
                    buffer.append(c)
                }

                if !closed {
                    throw DotEnvParseError(
                        path: path,
                        line: entryLine,
                        message: "Unterminated single-quoted value for '\(rawKey)'"
                    )
                }

                try consumeTrailingAfterQuote(
                    chars: chars,
                    count: count,
                    index: &index,
                    line: currentLine,
                    key: rawKey,
                    strict: strict,
                    path: path
                )
                parsedValue = buffer

            } else if quoteChar == "\"" {
                // Double-quoted value: escapes + ${...} interpolation + multiline supported
                index += 1
                var buffer = String()
                var closed = false

                while index < count {
                    let c = chars[index]
                    index += 1

                    if c == "\"" {
                        closed = true
                        break
                    }

                    if c == "\n" {
                        currentLine += 1
                        buffer.append("\n")
                        continue
                    }

                    if c == "\\" {
                        guard index < count else {
                            throw DotEnvParseError(
                                path: path,
                                line: entryLine,
                                message: "Unterminated escape sequence in value for '\(rawKey)'"
                            )
                        }
                        let escaped = chars[index]
                        index += 1
                        switch escaped {
                        case "n":
                            buffer.append("\n")
                        case "r":
                            buffer.append("\r")
                        case "t":
                            buffer.append("\t")
                        case "\"":
                            buffer.append("\"")
                        case "\\":
                            buffer.append("\\")
                        case "$":
                            buffer.append("$")
                        case "'":
                            buffer.append("'")
                        case "\n":
                            // Backslash-newline line continuation inside double quotes
                            currentLine += 1
                        case "u":
                            if let scalar = parseUnicodeEscape(chars: chars, count: count, index: &index) {
                                buffer.unicodeScalars.append(scalar)
                            } else {
                                buffer.append("\\")
                                buffer.append("u")
                            }
                        default:
                            buffer.append("\\")
                            buffer.append(escaped)
                        }
                        continue
                    }

                    if c == "$", expandVariables, index < count, chars[index] == "{" {
                        let expanded = try parseBracedInterpolation(
                            chars: chars,
                            count: count,
                            index: &index,
                            currentLine: &currentLine,
                            entryLine: entryLine,
                            path: path,
                            lookup: lookupVariable
                        )
                        buffer.append(expanded)
                        continue
                    }

                    buffer.append(c)
                }

                if !closed {
                    throw DotEnvParseError(
                        path: path,
                        line: entryLine,
                        message: "Unterminated double-quoted value for '\(rawKey)'"
                    )
                }

                try consumeTrailingAfterQuote(
                    chars: chars,
                    count: count,
                    index: &index,
                    line: currentLine,
                    key: rawKey,
                    strict: strict,
                    path: path
                )
                parsedValue = buffer

            } else {
                // Unquoted value: check for multiline PEM block (`-----BEGIN ...`) or single-line value
                let valueStart = index
                while index < count && chars[index] != "\n" {
                    index += 1
                }
                let rawFirstLine = String(chars[valueStart..<index])
                let trimmedFirstLine = trimTrailingHorizontalWhitespace(rawFirstLine)

                if trimmedFirstLine.hasPrefix("-----BEGIN ") && !trimmedFirstLine.contains("-----END ") {
                    var pemLines: [String] = [trimmedFirstLine]
                    var foundEnd = false

                    while index < count {
                        if chars[index] == "\n" {
                            index += 1
                            currentLine += 1
                        }
                        if index >= count {
                            break
                        }
                        let lineStart = index
                        while index < count && chars[index] != "\n" {
                            index += 1
                        }
                        let lineText = trimTrailingHorizontalWhitespace(String(chars[lineStart..<index]))
                        pemLines.append(lineText)
                        if lineText.hasPrefix("-----END ") && lineText.hasSuffix("-----") {
                            foundEnd = true
                            break
                        }
                    }

                    if !foundEnd {
                        throw DotEnvParseError(
                            path: path,
                            line: entryLine,
                            message: "Unterminated unquoted PEM block for '\(rawKey)'"
                        )
                    }

                    parsedValue = pemLines.joined(separator: "\n")
                } else {
                    // Standard unquoted value: strip inline `#` comment when preceded by whitespace,
                    // trim trailing whitespace, and optionally expand `${...}`.
                    let strippedUnquoted = stripUnquotedInlineComment(rawFirstLine)
                    let trimmedUnquoted = trimTrailingHorizontalWhitespace(strippedUnquoted)
                    if expandVariables {
                        parsedValue = try expandUnquotedString(
                            trimmedUnquoted,
                            entryLine: entryLine,
                            path: path,
                            lookup: lookupVariable
                        )
                    } else {
                        parsedValue = trimmedUnquoted
                    }
                }
            }

            entries.append(DotEnvEntry(key: rawKey, value: parsedValue, line: entryLine))
            localEnv[rawKey] = parsedValue
        }

        return entries
    }

    // MARK: - Helpers

    private static func consumeTrailingAfterQuote(
        chars: [Character],
        count: Int,
        index: inout Int,
        line: Int,
        key: String,
        strict: Bool,
        path: String?
    ) throws {
        while index < count && (chars[index] == " " || chars[index] == "\t") {
            index += 1
        }
        if index >= count || chars[index] == "\n" {
            return
        }
        if chars[index] == "#" {
            while index < count && chars[index] != "\n" {
                index += 1
            }
            return
        }
        if strict {
            throw DotEnvParseError(
                path: path,
                line: line,
                message: "Unexpected trailing characters after closing quote for '\(key)'"
            )
        }
        while index < count && chars[index] != "\n" {
            index += 1
        }
    }

    private static func parseUnicodeEscape(
        chars: [Character],
        count: Int,
        index: inout Int
    ) -> UnicodeScalar? {
        if index < count && chars[index] == "{" {
            let saved = index
            index += 1
            var hex = ""
            while index < count && chars[index] != "}" && hex.count <= 8 {
                hex.append(chars[index])
                index += 1
            }
            if index < count, chars[index] == "}", !hex.isEmpty,
               let codePoint = UInt32(hex, radix: 16),
               let scalar = UnicodeScalar(codePoint) {
                index += 1
                return scalar
            }
            index = saved
            return nil
        }

        guard index + 4 <= count else { return nil }
        let hex = String(chars[index..<(index + 4)])
        guard let codePoint = UInt32(hex, radix: 16),
              let scalar = UnicodeScalar(codePoint) else {
            return nil
        }
        index += 4
        return scalar
    }

    private static func stripUnquotedInlineComment(_ line: String) -> String {
        let chars = Array(line)
        for i in chars.indices {
            if chars[i] == "#", i > 0, (chars[i - 1] == " " || chars[i - 1] == "\t") {
                return String(chars[0..<i])
            }
        }
        return line
    }

    private static func trimTrailingHorizontalWhitespace(_ text: String) -> String {
        var result = text
        while let last = result.last, last == " " || last == "\t" {
            result.removeLast()
        }
        return result
    }

    private static func parseBracedInterpolation(
        chars: [Character],
        count: Int,
        index: inout Int,
        currentLine: inout Int,
        entryLine: Int,
        path: String?,
        lookup: (String) -> String?
    ) throws -> String {
        index += 1
        var depth = 1
        var exprChars: [Character] = []

        while index < count && depth > 0 {
            let c = chars[index]
            index += 1
            if c == "\n" {
                currentLine += 1
            }
            if c == "\\" && index < count {
                exprChars.append(c)
                let next = chars[index]
                index += 1
                if next == "\n" {
                    currentLine += 1
                }
                exprChars.append(next)
                continue
            }
            if c == "{" {
                depth += 1
                exprChars.append(c)
            } else if c == "}" {
                depth -= 1
                if depth > 0 {
                    exprChars.append(c)
                }
            } else {
                exprChars.append(c)
            }
        }

        guard depth == 0 else {
            throw DotEnvParseError(
                path: path,
                line: entryLine,
                message: "Unterminated '${...}' variable interpolation"
            )
        }

        return try evaluateInterpolationExpression(
            String(exprChars),
            entryLine: entryLine,
            path: path,
            lookup: lookup
        )
    }

    private static func evaluateInterpolationExpression(
        _ expr: String,
        entryLine: Int,
        path: String?,
        lookup: (String) -> String?
    ) throws -> String {
        let chars = Array(expr)
        var depth = 0
        var splitIndex: Int?
        var colonModifier = false

        for i in chars.indices {
            let c = chars[i]
            if c == "{", i > 0, chars[i - 1] == "$" {
                depth += 1
            } else if c == "}" && depth > 0 {
                depth -= 1
            } else if depth == 0 {
                if c == ":", i + 1 < chars.count, chars[i + 1] == "-" {
                    splitIndex = i
                    colonModifier = true
                    break
                } else if c == "-" {
                    splitIndex = i
                    colonModifier = false
                    break
                }
            }
        }

        let varName: String
        let rawDefault: String?

        if let splitIndex {
            varName = String(chars[0..<splitIndex]).trimmingCharacters(in: .whitespaces)
            let defaultStart = colonModifier ? (splitIndex + 2) : (splitIndex + 1)
            rawDefault = String(chars[defaultStart..<chars.count])
        } else {
            varName = expr.trimmingCharacters(in: .whitespaces)
            rawDefault = nil
        }

        guard !varName.isEmpty else {
            throw DotEnvParseError(
                path: path,
                line: entryLine,
                message: "Empty variable name in '${...}' interpolation"
            )
        }

        let resolved = lookup(varName)

        if let rawDefault {
            if colonModifier {
                if let resolved, !resolved.isEmpty {
                    return resolved
                }
                return try expandUnquotedString(rawDefault, entryLine: entryLine, path: path, lookup: lookup)
            } else {
                if let resolved {
                    return resolved
                }
                return try expandUnquotedString(rawDefault, entryLine: entryLine, path: path, lookup: lookup)
            }
        }

        return resolved ?? ""
    }

    private static func expandUnquotedString(
        _ text: String,
        entryLine: Int,
        path: String?,
        lookup: (String) -> String?
    ) throws -> String {
        let chars = Array(text)
        let count = chars.count
        var index = 0
        var dummyLine = entryLine
        var buffer = String()

        while index < count {
            let c = chars[index]
            index += 1

            if c == "\\", index < count, chars[index] == "$" {
                buffer.append("$")
                index += 1
                continue
            }

            if c == "$", index < count, chars[index] == "{" {
                let expanded = try parseBracedInterpolation(
                    chars: chars,
                    count: count,
                    index: &index,
                    currentLine: &dummyLine,
                    entryLine: entryLine,
                    path: path,
                    lookup: lookup
                )
                buffer.append(expanded)
                continue
            }

            buffer.append(c)
        }

        return buffer
    }
}
