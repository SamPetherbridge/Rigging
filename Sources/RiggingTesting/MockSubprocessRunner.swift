import Foundation
import RiggingCore

/// Actor-isolated mock `SubprocessRunner` that records CLI invocations and returns scripted
/// or closure-computed `SubprocessResult` responses without spawning real operating system processes.
///
/// ```swift
/// let runner = MockSubprocessRunner()
/// await runner.enqueue(exitCode: 0, stdout: "secret-value\n")
/// ```
public actor MockSubprocessRunner: SubprocessRunner {
    /// Captured parameters from a single ``run(executablePath:arguments:environment:stdin:timeout:)`` call.
    public struct Invocation: Sendable, Equatable {
        /// Absolute path to the executable binary passed to `run`.
        public let executablePath: String

        /// Command-line argument vector passed to the executable (excluding `argv[0]`).
        public let arguments: [String]

        /// Explicit subprocess environment dictionary, or `nil` when inheriting defaults.
        public let environment: [String: String]?

        /// Optional raw bytes piped to the subprocess's standard input.
        public let stdin: Data?

        /// Optional execution timeout configured for the subprocess call.
        public let timeout: Duration?

        /// Creates a recorded subprocess invocation snapshot.
        ///
        /// - Parameters:
        ///   - executablePath: Executable binary path.
        ///   - arguments: Command-line arguments passed to the binary.
        ///   - environment: Optional subprocess environment overrides.
        ///   - stdin: Optional raw bytes written to standard input.
        ///   - timeout: Optional timeout duration.
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

        /// Decodes ``stdin`` as a UTF-8 string when non-nil.
        public var stdinString: String? {
            guard let stdin else { return nil }
            return String(decoding: stdin, as: UTF8.self)
        }
    }

    /// Closure type capable of computing dynamic `SubprocessResult` responses (such as `op inject` boundary templates).
    public typealias Handler = @Sendable (Invocation) async throws -> SubprocessResult

    /// Ordered history of every subprocess invocation observed by this mock runner.
    public private(set) var invocations: [Invocation] = []

    /// Total number of ``run(executablePath:arguments:environment:stdin:timeout:)`` calls recorded.
    public var invocationCount: Int {
        invocations.count
    }

    private var queuedResponses: [Result<SubprocessResult, any Error>] = []
    private var handler: Handler?
    private var defaultResult: SubprocessResult

    /// Creates a mock subprocess runner returning `defaultResult` whenever no scripted item or handler is active.
    ///
    /// - Parameter defaultResult: Fallback `SubprocessResult` returned when the FIFO queue is empty and no handler is set.
    public init(
        defaultResult: SubprocessResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
    ) {
        self.defaultResult = defaultResult
    }

    /// Creates a mock subprocess runner seeded with a FIFO queue of `SubprocessResult` values.
    ///
    /// - Parameter results: Ordered `SubprocessResult` items dequeued on consecutive `run` calls.
    public init(results: [SubprocessResult]) {
        self.defaultResult = results.last ?? SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.queuedResponses = results.map { .success($0) }
    }

    /// Creates a mock subprocess runner seeded with a FIFO queue of `Result` responses.
    ///
    /// - Parameter scripted: Ordered success or failure responses dequeued on consecutive `run` calls.
    public init(scripted: [Result<SubprocessResult, any Error>]) {
        self.defaultResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.queuedResponses = scripted
    }

    /// Creates a mock subprocess runner backed by a dynamic async handler closure.
    ///
    /// - Parameter handler: Closure invoked for each ``Invocation`` when the FIFO queue is empty.
    public init(handler: @escaping Handler) {
        self.defaultResult = SubprocessResult(exitCode: 0, stdout: Data(), stderr: Data())
        self.handler = handler
    }

    /// Appends a scripted `SubprocessResult` to the FIFO response queue.
    ///
    /// - Parameter result: Result returned on the next `run` call.
    public func enqueue(_ result: SubprocessResult) {
        queuedResponses.append(.success(result))
    }

    /// Appends a scripted exit code, `stdout` string, and `stderr` string to the FIFO response queue.
    ///
    /// - Parameters:
    ///   - exitCode: Simulated process exit status (defaults to `0`).
    ///   - stdout: UTF-8 standard output payload.
    ///   - stderr: UTF-8 standard error payload.
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
    ///
    /// - Parameter error: Error thrown when dequeued by `run`.
    public func enqueueError(_ error: any Error) {
        queuedResponses.append(.failure(error))
    }

    /// Installs or clears the dynamic invocation handler.
    ///
    /// - Parameter handler: Closure computing responses dynamically, or `nil` to clear.
    public func setHandler(_ handler: Handler?) {
        self.handler = handler
    }

    /// Clears recorded ``invocations`` and any remaining queued responses.
    public func reset() {
        invocations.removeAll()
        queuedResponses.removeAll()
    }

    /// Records a subprocess invocation and returns the next queued response, dynamic handler result, or default result.
    ///
    /// - Parameters:
    ///   - executablePath: Absolute path to the executable binary.
    ///   - arguments: Command-line arguments passed to the executable.
    ///   - environment: Optional environment variable dictionary.
    ///   - stdin: Optional raw bytes written to standard input.
    ///   - timeout: Optional timeout duration.
    /// - Returns: Simulated `SubprocessResult` for the invocation.
    /// - Throws: Any scripted error enqueued via ``enqueueError(_:)`` or thrown by ``Handler``.
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
