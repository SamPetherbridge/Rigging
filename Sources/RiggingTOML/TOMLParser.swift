import Foundation

/// Structured syntax or semantic error thrown while parsing a TOML v1.0 document.
public struct TOMLParseError: Error, Sendable, Equatable, Hashable, CustomStringConvertible, LocalizedError {
    public let path: String?
    public let line: Int
    public let column: Int
    public let reason: String

    public init(path: String? = nil, line: Int, column: Int, reason: String) {
        self.path = path
        self.line = line
        self.column = column
        self.reason = reason
    }

    public var description: String {
        if let path, !path.isEmpty {
            return "TOML parse error in '\(path)' at \(line):\(column): \(reason)"
        }
        return "TOML parse error at \(line):\(column): \(reason)"
    }

    public var errorDescription: String? {
        description
    }
}

/// Typed value representation of a parsed TOML v1.0 node.
public enum TOMLValue: Sendable {
    case string(String)
    case int(Int64)
    case float(Double)
    case bool(Bool)
    /// Normalized RFC 3339 / ISO-8601 date, time, or datetime literal.
    case datetime(String)
    case array([TOMLValue])
    case table([String: TOMLValue])
}

extension TOMLValue: Equatable {
    public static func == (lhs: TOMLValue, rhs: TOMLValue) -> Bool {
        switch (lhs, rhs) {
        case (.string(let a), .string(let b)):
            return a == b
        case (.int(let a), .int(let b)):
            return a == b
        case (.float(let a), .float(let b)):
            if a.isNaN && b.isNaN { return true }
            return a == b
        case (.bool(let a), .bool(let b)):
            return a == b
        case (.datetime(let a), .datetime(let b)):
            return a == b
        case (.array(let a), .array(let b)):
            return a == b
        case (.table(let a), .table(let b)):
            return a == b
        default:
            return false
        }
    }
}

extension TOMLValue: Hashable {
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .string(let s):
            hasher.combine(0)
            hasher.combine(s)
        case .int(let i):
            hasher.combine(1)
            hasher.combine(i)
        case .float(let d):
            hasher.combine(2)
            if d.isNaN {
                hasher.combine(UInt64.max)
            } else if d == 0 {
                hasher.combine(0.0)
            } else {
                hasher.combine(d)
            }
        case .bool(let b):
            hasher.combine(3)
            hasher.combine(b)
        case .datetime(let dt):
            hasher.combine(4)
            hasher.combine(dt)
        case .array(let arr):
            hasher.combine(5)
            hasher.combine(arr)
        case .table(let tbl):
            hasher.combine(6)
            hasher.combine(tbl)
        }
    }
}

/// Pure-Swift, zero-dependency RFC-compliant TOML v1.0 parser.
public enum TOMLParser {
    /// Parses UTF-8 TOML data into a root dictionary of `TOMLValue` nodes.
    public static func parse(data: Data, path: String? = nil) throws -> [String: TOMLValue] {
        guard let text = String(data: data, encoding: .utf8) else {
            throw TOMLParseError(
                path: path,
                line: 1,
                column: 1,
                reason: "TOML input is not valid UTF-8."
            )
        }
        return try parse(text, path: path)
    }

    /// Parses a TOML v1.0 string into a root dictionary of `TOMLValue` nodes.
    public static func parse(_ text: String, path: String? = nil) throws -> [String: TOMLValue] {
        var engine = ParserEngine(text: text, path: path)
        return try engine.parseDocument()
    }
}

// MARK: - Internal Builder State

private enum TableOrigin: Equatable {
    case root
    case implicitHeader
    case explicitHeader
    case dottedKey(scopeID: Int)
    case inline
}

private final class BuilderTable {
    var origin: TableOrigin
    var entries: [String: BuilderNode] = [:]

    init(origin: TableOrigin) {
        self.origin = origin
    }

    func freeze() -> [String: TOMLValue] {
        var result: [String: TOMLValue] = [:]
        result.reserveCapacity(entries.count)
        for (key, node) in entries {
            result[key] = node.freeze()
        }
        return result
    }
}

private final class BuilderTableArray {
    var tables: [BuilderTable] = []

    func appendNewTable() -> BuilderTable {
        let table = BuilderTable(origin: .explicitHeader)
        tables.append(table)
        return table
    }

    var last: BuilderTable {
        tables[tables.count - 1]
    }
}

private enum BuilderNode {
    case table(BuilderTable)
    case tableArray(BuilderTableArray)
    case staticArray([BuilderNode])
    case scalar(TOMLValue)

    func freeze() -> TOMLValue {
        switch self {
        case .table(let tbl):
            return .table(tbl.freeze())
        case .tableArray(let arr):
            return .array(arr.tables.map { .table($0.freeze()) })
        case .staticArray(let items):
            return .array(items.map { $0.freeze() })
        case .scalar(let val):
            return val
        }
    }
}

// MARK: - Recursive-Descent TOML v1.0 Parser Engine

private struct ParserEngine {
    private let scalars: [UnicodeScalar]
    private let path: String?
    private var index: Int = 0
    private var line: Int = 1
    private var column: Int = 1
    private var nextScopeID: Int = 1

    init(text: String, path: String?) {
        var raw = Array(text.unicodeScalars)
        if raw.first == "\u{FEFF}" {
            raw.removeFirst()
        }
        self.scalars = raw
        self.path = path
    }

    private var isAtEnd: Bool {
        index >= scalars.count
    }

    private func peek(_ offset: Int = 0) -> UnicodeScalar? {
        let pos = index + offset
        guard pos >= 0 && pos < scalars.count else { return nil }
        return scalars[pos]
    }

    @discardableResult
    private mutating func advance() -> UnicodeScalar? {
        guard index < scalars.count else { return nil }
        let ch = scalars[index]
        index += 1
        if ch == "\n" {
            line += 1
            column = 1
        } else {
            column += 1
        }
        return ch
    }

    private func fail(_ reason: String, atLine errLine: Int? = nil, column errCol: Int? = nil) -> TOMLParseError {
        TOMLParseError(
            path: path,
            line: errLine ?? line,
            column: errCol ?? column,
            reason: reason
        )
    }

    // MARK: - Top-Level Document

    mutating func parseDocument() throws -> [String: TOMLValue] {
        let root = BuilderTable(origin: .root)
        var currentTable = root
        var currentScopeID = 0

        while !isAtEnd {
            try skipBlankLinesAndComments()
            if isAtEnd { break }

            if peek() == "[" {
                if peek(1) == "[" {
                    currentTable = try parseArrayOfTablesHeader(root: root)
                } else {
                    currentTable = try parseStandardTableHeader(root: root)
                }
                currentScopeID = nextScopeID
                nextScopeID += 1
                try expectEndOfStatement()
            } else {
                let keyStartLine = line
                let keyStartCol = column
                let keyPath = try parseKeyPath()
                skipSpacesAndTabs()
                guard peek() == "=" else {
                    throw fail("Expected '=' after key '\(keyPath.joined(separator: "."))'.")
                }
                advance() // '='
                skipSpacesAndTabs()
                let valueNode = try parseValue()
                try insertKeyValue(
                    keyPath: keyPath,
                    value: valueNode,
                    into: currentTable,
                    scopeID: currentScopeID,
                    line: keyStartLine,
                    column: keyStartCol
                )
                try expectEndOfStatement()
            }
        }

        return root.freeze()
    }

    // MARK: - Headers & Key Insertion

    private mutating func parseStandardTableHeader(root: BuilderTable) throws -> BuilderTable {
        let startLine = line
        let startCol = column
        advance() // '['
        skipSpacesAndTabs()
        if peek() == "]" {
            throw fail("Table header cannot be empty.", atLine: startLine, column: startCol)
        }
        let keyPath = try parseKeyPath()
        skipSpacesAndTabs()
        guard peek() == "]" else {
            throw fail("Expected closing ']' in table header.", atLine: line, column: column)
        }
        advance() // ']'

        var cursor = root
        for segment in keyPath.dropLast() {
            if let existing = cursor.entries[segment] {
                switch existing {
                case .table(let subTable):
                    switch subTable.origin {
                    case .implicitHeader, .explicitHeader, .root:
                        cursor = subTable
                    case .dottedKey:
                        throw fail(
                            "Cannot reopen table '\(keyPath.joined(separator: "."))' because '\(segment)' was already defined via dotted keys.",
                            atLine: startLine,
                            column: startCol
                        )
                    case .inline:
                        throw fail(
                            "Cannot extend inline table '\(segment)' via '[...]' header.",
                            atLine: startLine,
                            column: startCol
                        )
                    }
                case .tableArray(let tblArray):
                    cursor = tblArray.last
                case .staticArray, .scalar:
                    throw fail(
                        "Cannot define table '\(keyPath.joined(separator: "."))'; '\(segment)' is already a non-table value.",
                        atLine: startLine,
                        column: startCol
                    )
                }
            } else {
                let implicit = BuilderTable(origin: .implicitHeader)
                cursor.entries[segment] = .table(implicit)
                cursor = implicit
            }
        }

        let leaf = keyPath[keyPath.count - 1]
        if let existing = cursor.entries[leaf] {
            if case .table(let subTable) = existing, subTable.origin == .implicitHeader {
                subTable.origin = .explicitHeader
                return subTable
            }
            throw fail(
                "Duplicate or conflicting definition for table '[\(keyPath.joined(separator: "."))]'.",
                atLine: startLine,
                column: startCol
            )
        } else {
            let created = BuilderTable(origin: .explicitHeader)
            cursor.entries[leaf] = .table(created)
            return created
        }
    }

    private mutating func parseArrayOfTablesHeader(root: BuilderTable) throws -> BuilderTable {
        let startLine = line
        let startCol = column
        advance() // '['
        advance() // '['
        skipSpacesAndTabs()
        if peek() == "]" {
            throw fail("Array-of-tables header cannot be empty.", atLine: startLine, column: startCol)
        }
        let keyPath = try parseKeyPath()
        skipSpacesAndTabs()
        guard peek() == "]" && peek(1) == "]" else {
            throw fail("Expected closing ']]' in array-of-tables header.", atLine: line, column: column)
        }
        advance() // ']'
        advance() // ']'

        var cursor = root
        for segment in keyPath.dropLast() {
            if let existing = cursor.entries[segment] {
                switch existing {
                case .table(let subTable):
                    switch subTable.origin {
                    case .implicitHeader, .explicitHeader, .root:
                        cursor = subTable
                    case .dottedKey:
                        throw fail(
                            "Cannot define '[[\(keyPath.joined(separator: "."))]]' under dotted-key table '\(segment)'.",
                            atLine: startLine,
                            column: startCol
                        )
                    case .inline:
                        throw fail(
                            "Cannot extend inline table '\(segment)' via '[[...]]' header.",
                            atLine: startLine,
                            column: startCol
                        )
                    }
                case .tableArray(let tblArray):
                    cursor = tblArray.last
                case .staticArray, .scalar:
                    throw fail(
                        "Cannot define '[[\(keyPath.joined(separator: "."))]]'; '\(segment)' is already a non-table value.",
                        atLine: startLine,
                        column: startCol
                    )
                }
            } else {
                let implicit = BuilderTable(origin: .implicitHeader)
                cursor.entries[segment] = .table(implicit)
                cursor = implicit
            }
        }

        let leaf = keyPath[keyPath.count - 1]
        if let existing = cursor.entries[leaf] {
            guard case .tableArray(let tblArray) = existing else {
                throw fail(
                    "Cannot redefine '\(keyPath.joined(separator: "."))' as array of tables; already defined as another type.",
                    atLine: startLine,
                    column: startCol
                )
            }
            return tblArray.appendNewTable()
        } else {
            let tblArray = BuilderTableArray()
            let firstTable = tblArray.appendNewTable()
            cursor.entries[leaf] = .tableArray(tblArray)
            return firstTable
        }
    }

    private func insertKeyValue(
        keyPath: [String],
        value: BuilderNode,
        into baseTable: BuilderTable,
        scopeID: Int,
        line errLine: Int,
        column errCol: Int
    ) throws {
        var cursor = baseTable
        for segment in keyPath.dropLast() {
            if let existing = cursor.entries[segment] {
                guard case .table(let subTable) = existing else {
                    throw fail(
                        "Cannot set dotted key '\(keyPath.joined(separator: "."))'; '\(segment)' is not a table.",
                        atLine: errLine,
                        column: errCol
                    )
                }
                switch subTable.origin {
                case .dottedKey(let existingScope) where existingScope == scopeID:
                    cursor = subTable
                case .implicitHeader:
                    subTable.origin = .dottedKey(scopeID: scopeID)
                    cursor = subTable
                case .explicitHeader, .dottedKey, .inline, .root:
                    throw fail(
                        "Cannot extend closed or previously defined table '\(segment)' via dotted key '\(keyPath.joined(separator: "."))'.",
                        atLine: errLine,
                        column: errCol
                    )
                }
            } else {
                let subTable = BuilderTable(origin: .dottedKey(scopeID: scopeID))
                cursor.entries[segment] = .table(subTable)
                cursor = subTable
            }
        }

        let leaf = keyPath[keyPath.count - 1]
        guard cursor.entries[leaf] == nil else {
            throw fail(
                "Duplicate key '\(keyPath.joined(separator: "."))'.",
                atLine: errLine,
                column: errCol
            )
        }
        cursor.entries[leaf] = value
    }

    // MARK: - Keys

    private mutating func parseKeyPath() throws -> [String] {
        var segments: [String] = []
        segments.append(try parseSimpleKey())

        while true {
            skipSpacesAndTabs()
            guard peek() == "." else { break }
            advance() // '.'
            skipSpacesAndTabs()
            segments.append(try parseSimpleKey())
        }

        return segments
    }

    private mutating func parseSimpleKey() throws -> String {
        guard let ch = peek() else {
            throw fail("Unexpected end of input while expecting a key.")
        }

        if ch == "\"" {
            if peek(1) == "\"" && peek(2) == "\"" {
                throw fail("Multiline strings are not allowed as TOML keys.")
            }
            return try parseBasicString()
        }

        if ch == "'" {
            if peek(1) == "'" && peek(2) == "'" {
                throw fail("Multiline literal strings are not allowed as TOML keys.")
            }
            return try parseLiteralString()
        }

        var scalarsOut = String.UnicodeScalarView()
        while let current = peek(), Self.isBareKeyScalar(current) {
            scalarsOut.append(current)
            advance()
        }

        guard !scalarsOut.isEmpty else {
            throw fail("Invalid character '\(ch)' at start of bare key.")
        }

        return String(scalarsOut)
    }

    private static func isBareKeyScalar(_ s: UnicodeScalar) -> Bool {
        let v = s.value
        return (v >= 0x41 && v <= 0x5A) // A-Z
            || (v >= 0x61 && v <= 0x7A) // a-z
            || (v >= 0x30 && v <= 0x39) // 0-9
            || v == 0x5F                // _
            || v == 0x2D                // -
    }

    // MARK: - Values

    private mutating func parseValue() throws -> BuilderNode {
        guard let ch = peek() else {
            throw fail("Unexpected end of input while expecting a value.")
        }

        switch ch {
        case "\"":
            if peek(1) == "\"" && peek(2) == "\"" {
                return .scalar(.string(try parseMultilineBasicString()))
            }
            return .scalar(.string(try parseBasicString()))

        case "'":
            if peek(1) == "'" && peek(2) == "'" {
                return .scalar(.string(try parseMultilineLiteralString()))
            }
            return .scalar(.string(try parseLiteralString()))

        case "[":
            return try parseArray()

        case "{":
            return try parseInlineTable()

        case "t", "f":
            return .scalar(.bool(try parseBoolean()))

        default:
            return .scalar(try parseNumberOrDateTime())
        }
    }

    // MARK: - Strings

    private mutating func parseBasicString() throws -> String {
        let startLine = line
        let startCol = column
        advance() // opening '"'

        var out = String.UnicodeScalarView()
        while let ch = peek() {
            if ch == "\"" {
                advance()
                return String(out)
            }
            if ch == "\\" {
                advance() // '\'
                let escaped = try parseEscapeSequence()
                out.append(escaped)
                continue
            }
            if ch == "\n" || ch == "\r" {
                throw fail("Unescaped newline inside single-line basic string.", atLine: line, column: column)
            }
            if Self.isDisallowedStringControlChar(ch) {
                throw fail("Invalid control character U+\(String(ch.value, radix: 16, uppercase: true)) in string.")
            }
            out.append(ch)
            advance()
        }

        throw fail("Unterminated basic string.", atLine: startLine, column: startCol)
    }

    private mutating func parseMultilineBasicString() throws -> String {
        let startLine = line
        let startCol = column
        advance() // '"'
        advance() // '"'
        advance() // '"'

        // Trim immediate newline after opening `"""`
        consumeSingleNewlineIfPresent()

        var out = String.UnicodeScalarView()
        while !isAtEnd {
            if peek() == "\"" && peek(1) == "\"" && peek(2) == "\"" {
                // Count total consecutive quotes (3..5 valid: 0..2 trailing quotes + 3 closing quotes)
                var quoteCount = 0
                while peek() == "\"" && quoteCount < 6 {
                    advance()
                    quoteCount += 1
                }
                if quoteCount == 6 {
                    throw fail("Too many consecutive '\"' quotes at end of multiline basic string.")
                }
                let contentQuotes = quoteCount - 3
                for _ in 0..<contentQuotes {
                    out.append("\"")
                }
                return String(out)
            }

            guard let ch = peek() else { break }

            if ch == "\\" {
                advance() // '\'
                // Check line-ending backslash (escaped newline + whitespace continuation)
                if try consumeLineEndingBackslashIfPresent() {
                    continue
                }
                let escaped = try parseEscapeSequence()
                out.append(escaped)
                continue
            }

            if ch == "\r" {
                if peek(1) == "\n" {
                    advance()
                    advance()
                    out.append("\n")
                    continue
                }
                throw fail("Bare carriage return '\\r' is not allowed in multiline string.")
            }

            if ch == "\n" {
                advance()
                out.append("\n")
                continue
            }

            if Self.isDisallowedStringControlChar(ch) {
                throw fail("Invalid control character U+\(String(ch.value, radix: 16, uppercase: true)) in multiline string.")
            }

            out.append(ch)
            advance()
        }

        throw fail("Unterminated multiline basic string.", atLine: startLine, column: startCol)
    }

    private mutating func consumeLineEndingBackslashIfPresent() throws -> Bool {
        var lookahead = 0
        while let c = peek(lookahead), c == " " || c == "\t" {
            lookahead += 1
        }
        guard let nl = peek(lookahead), nl == "\n" || nl == "\r" else {
            return false
        }
        if nl == "\r" && peek(lookahead + 1) != "\n" {
            throw fail("Bare carriage return '\\r' after line-ending backslash.")
        }

        // Consume horizontal whitespace + newline, then all subsequent whitespace/newlines
        for _ in 0..<lookahead {
            advance()
        }
        consumeSingleNewlineIfPresent()
        while let next = peek() {
            if next == " " || next == "\t" || next == "\n" {
                advance()
            } else if next == "\r" && peek(1) == "\n" {
                advance()
                advance()
            } else {
                break
            }
        }
        return true
    }

    private mutating func parseEscapeSequence() throws -> UnicodeScalar {
        guard let esc = peek() else {
            throw fail("Unexpected end of input after '\\' in string.")
        }
        advance()
        switch esc {
        case "b": return "\u{0008}"
        case "t": return "\t"
        case "n": return "\n"
        case "f": return "\u{000C}"
        case "r": return "\r"
        case "\"": return "\""
        case "\\": return "\\"
        case "u":
            return try parseUnicodeHexEscape(digits: 4)
        case "U":
            return try parseUnicodeHexEscape(digits: 8)
        default:
            throw fail("Invalid escape sequence '\\\(esc)' in basic string.")
        }
    }

    private mutating func parseUnicodeHexEscape(digits: Int) throws -> UnicodeScalar {
        var hex = ""
        hex.reserveCapacity(digits)
        for _ in 0..<digits {
            guard let ch = peek(), Self.isHexDigit(ch) else {
                throw fail("Expected \(digits) hexadecimal digits in Unicode escape sequence.")
            }
            hex.unicodeScalars.append(ch)
            advance()
        }
        guard let codePoint = UInt32(hex, radix: 16),
              let scalar = UnicodeScalar(codePoint) else {
            throw fail("Invalid Unicode scalar value U+\(hex) in escape sequence.")
        }
        return scalar
    }

    private mutating func parseLiteralString() throws -> String {
        let startLine = line
        let startCol = column
        advance() // opening "'"

        var out = String.UnicodeScalarView()
        while let ch = peek() {
            if ch == "'" {
                advance()
                return String(out)
            }
            if ch == "\n" || ch == "\r" {
                throw fail("Newline is not allowed inside single-line literal string.", atLine: line, column: column)
            }
            if Self.isDisallowedStringControlChar(ch) {
                throw fail("Invalid control character U+\(String(ch.value, radix: 16, uppercase: true)) in literal string.")
            }
            out.append(ch)
            advance()
        }

        throw fail("Unterminated literal string.", atLine: startLine, column: startCol)
    }

    private mutating func parseMultilineLiteralString() throws -> String {
        let startLine = line
        let startCol = column
        advance() // "'"
        advance() // "'"
        advance() // "'"

        consumeSingleNewlineIfPresent()

        var out = String.UnicodeScalarView()
        while !isAtEnd {
            if peek() == "'" && peek(1) == "'" && peek(2) == "'" {
                var quoteCount = 0
                while peek() == "'" && quoteCount < 6 {
                    advance()
                    quoteCount += 1
                }
                if quoteCount == 6 {
                    throw fail("Too many consecutive ''' quotes at end of multiline literal string.")
                }
                let contentQuotes = quoteCount - 3
                for _ in 0..<contentQuotes {
                    out.append("'")
                }
                return String(out)
            }

            guard let ch = peek() else { break }
            if ch == "\r" {
                if peek(1) == "\n" {
                    advance()
                    advance()
                    out.append("\n")
                    continue
                }
                throw fail("Bare carriage return '\\r' is not allowed in multiline literal string.")
            }
            if ch == "\n" {
                advance()
                out.append("\n")
                continue
            }
            if Self.isDisallowedStringControlChar(ch) {
                throw fail("Invalid control character U+\(String(ch.value, radix: 16, uppercase: true)) in multiline literal string.")
            }
            out.append(ch)
            advance()
        }

        throw fail("Unterminated multiline literal string.", atLine: startLine, column: startCol)
    }

    // MARK: - Arrays & Inline Tables

    private mutating func parseArray() throws -> BuilderNode {
        let startLine = line
        let startCol = column
        advance() // '['

        var elements: [BuilderNode] = []
        while true {
            try skipWhitespaceAndCommentsInMultilineConstruct()
            if peek() == "]" {
                advance()
                return .staticArray(elements)
            }
            if isAtEnd {
                throw fail("Unterminated array.", atLine: startLine, column: startCol)
            }

            let element = try parseValue()
            elements.append(element)

            try skipWhitespaceAndCommentsInMultilineConstruct()
            if peek() == "," {
                advance()
                continue
            } else if peek() == "]" {
                advance()
                return .staticArray(elements)
            } else {
                throw fail("Expected ',' or ']' after array element.")
            }
        }
    }

    private mutating func parseInlineTable() throws -> BuilderNode {
        let startLine = line
        let startCol = column
        let inlineScope = nextScopeID
        nextScopeID += 1
        advance() // '{'

        let table = BuilderTable(origin: .inline)
        skipSpacesAndTabs()
        if peek() == "}" {
            advance()
            return .table(table)
        }

        while true {
            skipSpacesAndTabs()
            if peek() == "\n" || peek() == "\r" {
                throw fail("Newlines are not permitted inside TOML v1.0 inline tables.", atLine: line, column: column)
            }
            if isAtEnd {
                throw fail("Unterminated inline table.", atLine: startLine, column: startCol)
            }

            let keyLine = line
            let keyCol = column
            let keyPath = try parseKeyPath()
            skipSpacesAndTabs()
            guard peek() == "=" else {
                throw fail("Expected '=' after key in inline table.")
            }
            advance() // '='
            skipSpacesAndTabs()
            let val = try parseValue()
            try insertKeyValue(
                keyPath: keyPath,
                value: val,
                into: table,
                scopeID: inlineScope,
                line: keyLine,
                column: keyCol
            )

            skipSpacesAndTabs()
            if peek() == "}" {
                table.origin = .inline
                advance()
                return .table(table)
            } else if peek() == "," {
                advance()
                skipSpacesAndTabs()
                if peek() == "}" {
                    throw fail("Trailing commas are not permitted in TOML v1.0 inline tables.")
                }
                continue
            } else {
                throw fail("Expected ',' or '}' in inline table.")
            }
        }
    }

    // MARK: - Booleans, Numbers & RFC 3339 Dates/Times

    private mutating func parseBoolean() throws -> Bool {
        let tokenLine = line
        let tokenCol = column
        let raw = readRawScalarToken()
        if raw == "true" { return true }
        if raw == "false" { return false }
        throw fail("Invalid boolean literal '\(raw)'.", atLine: tokenLine, column: tokenCol)
    }

    private mutating func parseNumberOrDateTime() throws -> TOMLValue {
        let tokenLine = line
        let tokenCol = column
        var raw = readRawScalarToken()
        guard !raw.isEmpty else {
            throw fail("Expected scalar value.", atLine: tokenLine, column: tokenCol)
        }

        // RFC 3339 Offset/Local Date-Time allows a single space between YYYY-MM-DD and HH:MM:SS
        if Self.looksLikeDatePrefix(raw),
           peek() == " ",
           let d1 = peek(1), Self.isDigit(d1),
           let d2 = peek(2), Self.isDigit(d2),
           peek(3) == ":" {
            advance() // ' '
            let timePart = readRawScalarToken()
            raw += "T" + timePart
        }

        // Special float literals
        switch raw {
        case "inf", "+inf":
            return .float(.infinity)
        case "-inf":
            return .float(-.infinity)
        case "nan", "+nan", "-nan":
            return .float(.nan)
        default:
            break
        }

        // Date / Time check (`YYYY-MM-DD...` or `HH:MM:SS...`)
        if raw.contains("-") || raw.contains(":") {
            if let normalizedDT = try parseDateTimeIfApplicable(raw, line: tokenLine, column: tokenCol) {
                return .datetime(normalizedDT)
            }
        }

        // Non-decimal integer prefixes: 0x, 0o, 0b (no leading sign allowed in TOML v1.0)
        if raw.hasPrefix("0x") || raw.hasPrefix("0o") || raw.hasPrefix("0b") {
            let value = try parseRadixInteger(raw, line: tokenLine, column: tokenCol)
            return .int(value)
        }
        if raw.hasPrefix("0X") || raw.hasPrefix("0O") || raw.hasPrefix("0B")
            || raw.hasPrefix("+0x") || raw.hasPrefix("-0x")
            || raw.hasPrefix("+0o") || raw.hasPrefix("-0o")
            || raw.hasPrefix("+0b") || raw.hasPrefix("-0b") {
            throw fail("Invalid integer literal '\(raw)'.", atLine: tokenLine, column: tokenCol)
        }

        // Decimal integer or float
        if raw.contains(".") || raw.contains("e") || raw.contains("E") {
            let d = try parseDecimalFloat(raw, line: tokenLine, column: tokenCol)
            return .float(d)
        } else {
            let i = try parseDecimalInteger(raw, line: tokenLine, column: tokenCol)
            return .int(i)
        }
    }

    private mutating func readRawScalarToken() -> String {
        var out = String.UnicodeScalarView()
        while let ch = peek() {
            if ch == " " || ch == "\t" || ch == "\n" || ch == "\r"
                || ch == "#" || ch == "," || ch == "]" || ch == "}" {
                break
            }
            out.append(ch)
            advance()
        }
        return String(out)
    }

    private func parseRadixInteger(_ raw: String, line errLine: Int, column errCol: Int) throws -> Int64 {
        let prefix = String(raw.prefix(2))
        let body = String(raw.dropFirst(2))
        let radix: Int
        let isValidDigit: (UnicodeScalar) -> Bool

        switch prefix {
        case "0x":
            radix = 16
            isValidDigit = Self.isHexDigit
        case "0o":
            radix = 8
            isValidDigit = { $0.value >= 0x30 && $0.value <= 0x37 }
        case "0b":
            radix = 2
            isValidDigit = { $0 == "0" || $0 == "1" }
        default:
            throw fail("Invalid radix prefix '\(prefix)'.", atLine: errLine, column: errCol)
        }

        guard try validateUnderscoreDigits(body, isValidDigit: isValidDigit) else {
            throw fail("Invalid digits or underscores in integer '\(raw)'.", atLine: errLine, column: errCol)
        }

        let cleaned = body.replacingOccurrences(of: "_", with: "")
        guard let intVal = Int64(cleaned, radix: radix) else {
            throw fail("Integer literal '\(raw)' overflows 64-bit signed integer.", atLine: errLine, column: errCol)
        }
        return intVal
    }

    private func parseDecimalInteger(_ raw: String, line errLine: Int, column errCol: Int) throws -> Int64 {
        var slice = Substring(raw)
        if slice.first == "+" || slice.first == "-" {
            slice = slice.dropFirst()
        }
        guard !slice.isEmpty else {
            throw fail("Invalid integer literal '\(raw)'.", atLine: errLine, column: errCol)
        }
        if slice.count > 1 && slice.first == "0" {
            throw fail("Leading zeros are not permitted in decimal integer '\(raw)'.", atLine: errLine, column: errCol)
        }
        guard try validateUnderscoreDigits(String(slice), isValidDigit: Self.isDigit) else {
            throw fail("Invalid integer literal '\(raw)'.", atLine: errLine, column: errCol)
        }

        let cleaned = raw.replacingOccurrences(of: "_", with: "")
        guard let value = Int64(cleaned) else {
            throw fail("Integer literal '\(raw)' is out of 64-bit signed range.", atLine: errLine, column: errCol)
        }
        return value
    }

    private func parseDecimalFloat(_ raw: String, line errLine: Int, column errCol: Int) throws -> Double {
        var rest = Substring(raw)
        if rest.first == "+" || rest.first == "-" {
            rest = rest.dropFirst()
        }

        // Split exponent first
        let mantissa: Substring
        let exponentPart: Substring?
        if let eIdx = rest.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mantissa = rest[..<eIdx]
            let afterE = rest[rest.index(after: eIdx)...]
            if afterE.contains(where: { $0 == "e" || $0 == "E" || $0 == "." }) {
                throw fail("Invalid float exponent in '\(raw)'.", atLine: errLine, column: errCol)
            }
            exponentPart = afterE
        } else {
            mantissa = rest
            exponentPart = nil
        }

        // Validate mantissa (either integer or integer.fraction)
        if let dotIdx = mantissa.firstIndex(of: ".") {
            let intPart = mantissa[..<dotIdx]
            let fracPart = mantissa[mantissa.index(after: dotIdx)...]
            if fracPart.contains(".") || intPart.isEmpty || fracPart.isEmpty {
                throw fail("Invalid decimal point placement in float '\(raw)'.", atLine: errLine, column: errCol)
            }
            if intPart.count > 1 && intPart.first == "0" {
                throw fail("Leading zeros are not permitted in float '\(raw)'.", atLine: errLine, column: errCol)
            }
            guard try validateUnderscoreDigits(String(intPart), isValidDigit: Self.isDigit),
                  try validateUnderscoreDigits(String(fracPart), isValidDigit: Self.isDigit) else {
                throw fail("Invalid digits or underscores in float '\(raw)'.", atLine: errLine, column: errCol)
            }
        } else {
            if mantissa.isEmpty || (mantissa.count > 1 && mantissa.first == "0") {
                throw fail("Invalid float mantissa in '\(raw)'.", atLine: errLine, column: errCol)
            }
            guard try validateUnderscoreDigits(String(mantissa), isValidDigit: Self.isDigit) else {
                throw fail("Invalid digits or underscores in float '\(raw)'.", atLine: errLine, column: errCol)
            }
        }

        if var exp = exponentPart {
            if exp.first == "+" || exp.first == "-" {
                exp = exp.dropFirst()
            }
            guard !exp.isEmpty,
                  try validateUnderscoreDigits(String(exp), isValidDigit: Self.isDigit) else {
                throw fail("Invalid exponent digits in float '\(raw)'.", atLine: errLine, column: errCol)
            }
        }

        let cleaned = raw.replacingOccurrences(of: "_", with: "")
        guard let value = Double(cleaned) else {
            throw fail("Invalid floating-point literal '\(raw)'.", atLine: errLine, column: errCol)
        }
        return value
    }

    private func validateUnderscoreDigits(
        _ s: String,
        isValidDigit: (UnicodeScalar) -> Bool
    ) throws -> Bool {
        let chars = Array(s.unicodeScalars)
        guard !chars.isEmpty else { return false }
        if chars.first == "_" || chars.last == "_" {
            return false
        }
        for i in chars.indices {
            let c = chars[i]
            if c == "_" {
                if !isValidDigit(chars[i - 1]) || !isValidDigit(chars[i + 1]) {
                    return false
                }
            } else if !isValidDigit(c) {
                return false
            }
        }
        return true
    }

    // MARK: - RFC 3339 Date / Time Validation

    private static func looksLikeDatePrefix(_ s: String) -> Bool {
        let chars = Array(s.unicodeScalars)
        guard chars.count == 10 else { return false }
        return isDigit(chars[0]) && isDigit(chars[1]) && isDigit(chars[2]) && isDigit(chars[3])
            && chars[4] == "-"
            && isDigit(chars[5]) && isDigit(chars[6])
            && chars[7] == "-"
            && isDigit(chars[8]) && isDigit(chars[9])
    }

    private func parseDateTimeIfApplicable(
        _ raw: String,
        line errLine: Int,
        column errCol: Int
    ) throws -> String? {
        // Local time: HH:MM:SS[.frac]
        if raw.count >= 8 && !raw.hasPrefix("+") && !raw.hasPrefix("-") {
            let scalars = Array(raw.unicodeScalars)
            if scalars.count >= 8 && scalars[2] == ":" && scalars[5] == ":" {
                guard try validateTimePart(raw) else {
                    throw fail("Invalid local time '\(raw)'.", atLine: errLine, column: errCol)
                }
                return raw
            }
        }

        // Date or Date-Time: YYYY-MM-DD...
        let scalars = Array(raw.unicodeScalars)
        guard scalars.count >= 10,
              Self.isDigit(scalars[0]), Self.isDigit(scalars[1]), Self.isDigit(scalars[2]), Self.isDigit(scalars[3]),
              scalars[4] == "-",
              Self.isDigit(scalars[5]), Self.isDigit(scalars[6]),
              scalars[7] == "-",
              Self.isDigit(scalars[8]), Self.isDigit(scalars[9]) else {
            return nil
        }

        let datePrefix = String(String.UnicodeScalarView(scalars[0..<10]))
        guard Self.validateCalendarDate(datePrefix) else {
            throw fail("Invalid calendar date '\(datePrefix)' in '\(raw)'.", atLine: errLine, column: errCol)
        }

        if scalars.count == 10 {
            return datePrefix
        }

        let sep = scalars[10]
        guard sep == "T" || sep == "t" else {
            throw fail("Invalid date-time separator '\(sep)' in '\(raw)'.", atLine: errLine, column: errCol)
        }

        let remainder = String(String.UnicodeScalarView(scalars[11...]))
        let (timePart, offsetPart) = try splitTimeAndOffset(remainder, fullLiteral: raw, line: errLine, column: errCol)
        guard try validateTimePart(timePart) else {
            throw fail("Invalid time component '\(timePart)' in '\(raw)'.", atLine: errLine, column: errCol)
        }

        if let offsetPart {
            guard Self.validateOffsetPart(offsetPart) else {
                throw fail("Invalid timezone offset '\(offsetPart)' in '\(raw)'.", atLine: errLine, column: errCol)
            }
            let normalizedOffset = offsetPart == "z" ? "Z" : offsetPart
            return "\(datePrefix)T\(timePart)\(normalizedOffset)"
        }

        return "\(datePrefix)T\(timePart)"
    }

    private func splitTimeAndOffset(
        _ remainder: String,
        fullLiteral: String,
        line errLine: Int,
        column errCol: Int
    ) throws -> (String, String?) {
        if remainder.hasSuffix("Z") || remainder.hasSuffix("z") {
            return (String(remainder.dropLast()), String(remainder.suffix(1)))
        }
        // Look for +HH:MM or -HH:MM after HH:MM:SS (index >= 8)
        let chars = Array(remainder.unicodeScalars)
        if chars.count > 8 {
            for idx in 8..<chars.count where chars[idx] == "+" || chars[idx] == "-" {
                let t = String(String.UnicodeScalarView(chars[0..<idx]))
                let off = String(String.UnicodeScalarView(chars[idx...]))
                return (t, off)
            }
        }
        return (remainder, nil)
    }

    private static func validateCalendarDate(_ dateStr: String) -> Bool {
        let parts = dateStr.split(separator: "-")
        guard parts.count == 3,
              let year = Int(parts[0]),
              let month = Int(parts[1]),
              let day = Int(parts[2]),
              (1...12).contains(month) else {
            return false
        }
        let isLeap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
        let daysInMonth: Int
        switch month {
        case 1, 3, 5, 7, 8, 10, 12: daysInMonth = 31
        case 4, 6, 9, 11: daysInMonth = 30
        case 2: daysInMonth = isLeap ? 29 : 28
        default: return false
        }
        return (1...daysInMonth).contains(day)
    }

    private func validateTimePart(_ timeStr: String) throws -> Bool {
        let mainAndFrac = timeStr.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        let hms = mainAndFrac[0]
        let hmsParts = hms.split(separator: ":", omittingEmptySubsequences: false)
        guard hmsParts.count == 3,
              hmsParts[0].count == 2, hmsParts[1].count == 2, hmsParts[2].count == 2,
              let hour = Int(hmsParts[0]), (0...23).contains(hour),
              let minute = Int(hmsParts[1]), (0...59).contains(minute),
              let second = Int(hmsParts[2]), (0...60).contains(second) else {
            return false
        }
        if mainAndFrac.count == 2 {
            let frac = mainAndFrac[1]
            guard !frac.isEmpty && frac.unicodeScalars.allSatisfy(Self.isDigit) else {
                return false
            }
        }
        return true
    }

    private static func validateOffsetPart(_ offsetStr: String) -> Bool {
        if offsetStr == "Z" || offsetStr == "z" {
            return true
        }
        let chars = Array(offsetStr.unicodeScalars)
        guard chars.count == 6,
              (chars[0] == "+" || chars[0] == "-"),
              isDigit(chars[1]), isDigit(chars[2]),
              chars[3] == ":",
              isDigit(chars[4]), isDigit(chars[5]) else {
            return false
        }
        let hh = Int(String(String.UnicodeScalarView(chars[1...2]))) ?? -1
        let mm = Int(String(String.UnicodeScalarView(chars[4...5]))) ?? -1
        return (0...23).contains(hh) && (0...59).contains(mm)
    }

    // MARK: - Whitespace, Comments & Statement Boundaries

    private mutating func skipSpacesAndTabs() {
        while let ch = peek(), ch == " " || ch == "\t" {
            advance()
        }
    }

    private mutating func consumeSingleNewlineIfPresent() {
        if peek() == "\n" {
            advance()
        } else if peek() == "\r" && peek(1) == "\n" {
            advance()
            advance()
        }
    }

    private mutating func skipCommentToEndOfLine() throws {
        guard peek() == "#" else { return }
        advance() // '#'
        while let ch = peek() {
            if ch == "\n" {
                break
            }
            if ch == "\r" {
                if peek(1) == "\n" { break }
                throw fail("Bare carriage return '\\r' is not permitted in TOML comment.")
            }
            if Self.isDisallowedStringControlChar(ch) {
                throw fail("Invalid control character U+\(String(ch.value, radix: 16, uppercase: true)) in TOML comment.")
            }
            advance()
        }
    }

    private mutating func skipBlankLinesAndComments() throws {
        while !isAtEnd {
            skipSpacesAndTabs()
            if peek() == "#" {
                try skipCommentToEndOfLine()
            }
            if peek() == "\n" {
                advance()
            } else if peek() == "\r" {
                guard peek(1) == "\n" else {
                    throw fail("Bare carriage return '\\r' is not permitted in TOML.")
                }
                advance()
                advance()
            } else {
                break
            }
        }
    }

    private mutating func skipWhitespaceAndCommentsInMultilineConstruct() throws {
        try skipBlankLinesAndComments()
        skipSpacesAndTabs()
    }

    private mutating func expectEndOfStatement() throws {
        skipSpacesAndTabs()
        if peek() == "#" {
            try skipCommentToEndOfLine()
        }
        if isAtEnd {
            return
        }
        if peek() == "\n" {
            advance()
            return
        }
        if peek() == "\r" && peek(1) == "\n" {
            advance()
            advance()
            return
        }
        throw fail("Expected newline or end of file after statement.")
    }

    private static func isDigit(_ s: UnicodeScalar) -> Bool {
        s.value >= 0x30 && s.value <= 0x39
    }

    private static func isHexDigit(_ s: UnicodeScalar) -> Bool {
        let v = s.value
        return (v >= 0x30 && v <= 0x39)
            || (v >= 0x41 && v <= 0x46)
            || (v >= 0x61 && v <= 0x66)
    }

    private static func isDisallowedStringControlChar(_ s: UnicodeScalar) -> Bool {
        let v = s.value
        // Allow TAB (0x09); disallow 0x00..0x08, 0x0A..0x1F, 0x7F
        return (v <= 0x08) || (v >= 0x0A && v <= 0x1F) || v == 0x7F
    }
}
