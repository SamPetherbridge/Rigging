import Foundation
import Synchronization

/// Thread-safe diagnostic redactor that tracks resolved secret plaintext and scrubs
/// accidental occurrences from error messages, logs, and diagnostic payloads.
public final class DiagnosticRedactor: Sendable {
    /// Replacement mask substituted for any registered secret substring.
    public static let redactedPlaceholder = "**********"

    /// Minimum trimmed character length required for a secret or line fragment to be registered.
    public let minimumLength: Int

    private struct State: Sendable {
        var secrets: Set<String> = []
        var sortedSecrets: [String] = []

        mutating func insert(_ candidate: String) -> Bool {
            guard candidate != DiagnosticRedactor.redactedPlaceholder else {
                return false
            }
            return secrets.insert(candidate).inserted
        }

        mutating func rebuildSorted() {
            sortedSecrets = secrets.sorted { lhs, rhs in
                if lhs.utf8.count != rhs.utf8.count {
                    return lhs.utf8.count > rhs.utf8.count
                }
                return lhs > rhs
            }
        }
    }

    private let state = Mutex(State())

    /// Creates a new redactor with the specified minimum secret length threshold (default `6`).
    public init(minimumLength: Int = 6) {
        self.minimumLength = max(1, minimumLength)
    }

    /// Registers a secret string (and any non-header/non-footer multiline segments >= `minimumLength`)
    /// for subsequent scrubbing.
    public func register(_ secret: String) {
        let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        var candidates: [String] = []
        if trimmed.count >= minimumLength {
            candidates.append(trimmed)
            if trimmed.contains("\r\n") {
                let normalized = trimmed.replacingOccurrences(of: "\r\n", with: "\n")
                if normalized.count >= minimumLength {
                    candidates.append(normalized)
                }
            }
        }

        // Split multiline secrets (e.g. PEM private keys or certificates) so partial single-line
        // leaks in parser diagnostics are also scrubbed, while skipping public PEM armor boundaries.
        let newlineLines = trimmed.split(whereSeparator: \.isNewline).map(String.init)
        if newlineLines.count > 1 {
            for rawLine in newlineLines {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.count >= minimumLength && !Self.isPEMArmorBoundary(line) {
                    candidates.append(line)
                }
            }
        }

        // Also handle escaped "\n" multiline payloads (such as inline PEM strings prior to normalization).
        if trimmed.contains("\\n") {
            let escapedLines = trimmed.components(separatedBy: "\\n")
            if escapedLines.count > 1 {
                for rawLine in escapedLines {
                    let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                    if line.count >= minimumLength && !Self.isPEMArmorBoundary(line) {
                        candidates.append(line)
                    }
                }
            }
        }

        guard !candidates.isEmpty else { return }

        state.withLock { state in
            var changed = false
            for candidate in candidates where state.insert(candidate) {
                changed = true
            }
            if changed {
                state.rebuildSorted()
            }
        }
    }

    /// Registers secret bytes for scrubbing (as UTF-8 text when valid, or Base64 for raw binary data).
    public func register(_ data: Data) {
        guard !data.isEmpty else { return }
        if let utf8 = String(data: data, encoding: .utf8) {
            register(utf8)
        } else if data.count >= minimumLength {
            let base64 = data.base64EncodedString()
            if base64.count >= minimumLength {
                register(base64)
            }
        }
    }

    /// Registers a secret byte array for scrubbing.
    public func register(_ bytes: [UInt8]) {
        register(Data(bytes))
    }

    /// Replaces every registered secret substring in `text` (longest match first) with `"**********"`.
    public func scrub(_ text: String) -> String {
        guard !text.isEmpty else { return text }

        let patterns = state.withLock { $0.sortedSecrets }
        guard !patterns.isEmpty else { return text }
        guard patterns.contains(where: { text.contains($0) }) else { return text }

        enum Segment {
            case plain(String)
            case redacted
        }

        var segments: [Segment] = [.plain(text)]

        for pattern in patterns {
            var next: [Segment] = []
            next.reserveCapacity(segments.count)

            for segment in segments {
                switch segment {
                case .redacted:
                    next.append(.redacted)
                case .plain(let chunk):
                    if chunk.isEmpty || !chunk.contains(pattern) {
                        next.append(.plain(chunk))
                    } else {
                        let parts = chunk.components(separatedBy: pattern)
                        for (index, part) in parts.enumerated() {
                            if index > 0 {
                                next.append(.redacted)
                            }
                            if !part.isEmpty {
                                next.append(.plain(part))
                            }
                        }
                    }
                }
            }

            segments = next
        }

        var output = ""
        output.reserveCapacity(text.utf8.count)
        for segment in segments {
            switch segment {
            case .plain(let chunk):
                output.append(chunk)
            case .redacted:
                output.append(Self.redactedPlaceholder)
            }
        }
        return output
    }

    /// Number of distinct secret patterns currently registered.
    public var registeredPatternCount: Int {
        state.withLock { $0.secrets.count }
    }

    private static func isPEMArmorBoundary(_ line: String) -> Bool {
        (line.hasPrefix("-----BEGIN ") || line.hasPrefix("-----END ")) && line.hasSuffix("-----")
    }
}
