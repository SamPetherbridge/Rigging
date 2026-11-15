import Foundation
import RiggingCore

/// Actor-isolated mock `SubprocessRunner` that records CLI invocations and returns scripted
/// or closure-computed `SubprocessResult` responses without spawning real OS processes.
public actor MockSubprocessRunner: SubprocessRunner {
    /// Captured parameters from a single `SubprocessRunner.run(...)` call.
    public struct Invocation: Sendable, Equatable {
        public let executablePath: String
        public let arguments: [String]
        public let environment: [String: String]?
        public let stdin: Data?
        public let timeout: Duration?

        public init(
            executablePath: String,
            arguments: [String],
            environment: [String: String]? = nil,
            stdin: Data? = nil,
            timeout: Duration? = nil
        ) {
            self.executablePath = executablePath
            self.arguments = arguments
            self.environment = environment
            self.stdin = stdin
            self.timeout = timeout
        }

        /// Decodes `stdin` as a UTF-8 string when non-nil.
        public var stdinString: String? {
            guard let stdin else { return nil }
            return String(decoding: stdin, as: UTF8.self)
        }
    }

    /// Closure type capable of computing dynamic `SubprocessResult` responses (such as `op inject` boundary templates).
    public typealias Handler = @Sendable (Invocation) async throws -> SubprocessResult

    /// Ordered history of every subprocess invocation observed by this mock runner.
    public private(set) var invocations: [Invocation] = []

    /// Total number of `run(...)` calls recorded.
    public var invocationCount: Int {
        invocations.count
    }

    private var queuedResponses: [Result<SubprocessResult, any Error>] = []
    private var handler: Handler?
    private var defaultResult: SubprocessResult

    /// Creates a mock subprocess runner returning `defaultResult` whenever no scripted item or handler is active.
    public init(
        defaultResult: SubprocessResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
    ) {
        self.defaultResult = defaultResult
    }

    /// Creates a mock subprocess runner seeded with a FIFO queue of `SubprocessResult` values.
    public init(results: [SubprocessResult]) {
        self.defaultResult = results.last ?? SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.queuedResponses = results.map { .success($0) }
    }

    /// Creates a mock subprocess runner seeded with a FIFO queue of `Result` responses.
    public init(scripted: [Result<SubprocessResult, any Error>]) {
        self.defaultResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.queuedResponses = scripted
    }

    /// Creates a mock subprocess runner backed by a dynamic async handler closure.
    public init(handler: @escaping Handler) {
        self.defaultResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.handler = handler
    }

    /// Appends a scripted `SubprocessResult` to the FIFO response queue.
    public func enqueue(_ result: SubprocessResult) {
        queuedResponses.append(.success(result))
    }

    /// Appends a scripted exit code, stdout string, and stderr string to the FIFO response queue.
    public func enqueue(exitCode: Int32 = 0, stdout: String = "", stderr: String = "") {
        queuedResponses.append(
            .success(
                SubprocessResult(
                    exitCode: exitCode,
                    stdout: Data(stdout.utf8),
                    stderr: Data(stderr.utf8)
                )
            )
        )
    }

    /// Appends a scripted error to be thrown on the next invocation.
    public func enqueueError(_ error: any Error) {
        queuedResponses.append(.failure(error))
    }

    /// Installs or clears the dynamic invocation handler.
    public func setHandler(_ handler: Handler?) {
        self.handler = handler
    }

    /// Clears recorded invocations and any remaining queued responses.
    public func reset() {
        invocations.removeAll()
        queuedResponses.removeAll()
    }

    public func run(
        executablePath: String,
        arguments: [String],
        environment: [String: String]?,
        stdin: Data?,
        timeout: Duration?
    ) async throws -> SubprocessResult {
        let invocation = Invocation(
            executablePath: executablePath,
            arguments: arguments,
            environment: environment,
            stdin: stdin,
            timeout: timeout
        )
        invocations.append(invocation)

        if !queuedResponses.isEmpty {
            let next = queuedResponses.removeFirst()
            return try next.get()
        }

        if let handler {
            return try await handler(invocation)
        }

        return defaultResult
    }
}
