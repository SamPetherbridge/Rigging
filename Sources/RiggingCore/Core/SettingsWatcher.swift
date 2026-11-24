import Foundation
#if canImport(Dispatch)
import Dispatch
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Actor-isolated live configuration reloader for long-running services, daemons, and applications.
///
/// `SettingsWatcher` monitors configuration files (via `DispatchSource` filesystem events on macOS
/// plus portable digest polling on Linux and mock filesystems) and optionally reloads on POSIX `SIGHUP`.
/// Rapid file edits are debounced, and ``current`` is swapped atomically **only** when the candidate
/// snapshot passes full schema, cross-field, and secret validation—preserving the last known-good
/// configuration if an operator saves an invalid intermediate edit.
///
/// ```swift
/// let watcher = try await SettingsWatcher<AppSettings>.start(reloadOnSIGHUP: true)
/// for await updated in await watcher.updates() {
///     await server.reconfigure(with: updated)
/// }
/// ```
public actor SettingsWatcher<Settings: RiggedSettings> {
    /// Most recently validated configuration snapshot.
    public private(set) var current: Settings

    /// Whether POSIX `SIGHUP` signals trigger an immediate ``reloadNow()`` pass.
    public let reloadOnSIGHUP: Bool

    private let context: SettingsContext
    private let overrides: [SettingOverride]
    private let watchedPaths: [String]
    private let pollInterval: Duration
    private let debounce: Duration
    private let onError: (@Sendable (any Error) -> Void)?

    private var subscribers: [UUID: AsyncStream<Settings>.Continuation] = [:]
    private var monitorTask: Task<Void, Never>?
    private var lastSnapshotDigests: [String: Data?] = [:]
    private var isStopped = false

    #if canImport(Dispatch) && os(macOS)
    private var dispatchSources: [any DispatchSourceFileSystemObject] = []
    #endif

    #if canImport(Dispatch) && (canImport(Darwin) || canImport(Glibc) || canImport(Musl))
    private var sighupSource: (any DispatchSourceSignal)?
    #endif

    /// Creates a configuration watcher initialized with an already-loaded `Settings` value.
    ///
    /// Call ``beginMonitoring()`` after initialization to start background change detection, or use
    /// ``start(context:overrides:watchedPaths:pollInterval:debounce:reloadOnSIGHUP:onError:)`` to load
    /// and begin monitoring in one step.
    ///
    /// - Parameters:
    ///   - initial: Initial validated settings snapshot.
    ///   - context: Execution context used on subsequent reloads.
    ///   - overrides: Explicit CLI or programmatic overrides preserved across reloads.
    ///   - watchedPaths: Additional file paths to monitor alongside configured `.env`, project, and XDG files.
    ///   - pollInterval: Interval between digest checks across watched files.
    ///   - debounce: Quiet-period delay applied after detecting a file modification before reloading.
    ///   - reloadOnSIGHUP: When `true`, installs a `SIGHUP` signal listener that triggers ``reloadNow()``.
    ///   - onError: Optional callback invoked when a background reload fails validation.
    public init(
        initial: Settings,
        context: SettingsContext = Settings.makeDefaultContext(),
        overrides: [SettingOverride] = [],
        watchedPaths: [String] = [],
        pollInterval: Duration = .seconds(2),
        debounce: Duration = .milliseconds(200),
        reloadOnSIGHUP: Bool = false,
        onError: (@Sendable (any Error) -> Void)? = nil
    ) {
        self.current = initial
        self.context = context
        self.overrides = overrides
        self.watchedPaths = Self.resolveCandidateWatchPaths(
            explicit: watchedPaths,
            configuration: Settings.configuration,
            context: context
        )
        self.pollInterval = pollInterval
        self.debounce = debounce
        self.reloadOnSIGHUP = reloadOnSIGHUP
        self.onError = onError
        self.lastSnapshotDigests = Self.captureFileSnapshots(
            paths: self.watchedPaths,
            fileSystem: context.fileSystem
        )
    }

    /// Loads the initial `Settings` snapshot and starts background file and optional `SIGHUP` monitoring.
    ///
    /// - Parameters:
    ///   - context: Execution context used for the initial load and subsequent reloads.
    ///   - overrides: Explicit CLI or programmatic overrides preserved across reloads.
    ///   - watchedPaths: Additional file paths to monitor alongside configured `.env`, project, and XDG files.
    ///   - pollInterval: Interval between digest checks across watched files.
    ///   - debounce: Quiet-period delay applied after detecting a file modification before reloading.
    ///   - reloadOnSIGHUP: When `true`, installs a POSIX `SIGHUP` listener that triggers ``reloadNow()``.
    ///   - onError: Optional callback invoked when a background reload fails validation.
    /// - Returns: Active ``SettingsWatcher`` holding the validated initial snapshot.
    /// - Throws: ``SettingsValidationError`` if the initial configuration fails to load.
    public static func start(
        context: SettingsContext = Settings.makeDefaultContext(),
        overrides: [SettingOverride] = [],
        watchedPaths: [String] = [],
        pollInterval: Duration = .seconds(2),
        debounce: Duration = .milliseconds(200),
        reloadOnSIGHUP: Bool = false,
        onError: (@Sendable (any Error) -> Void)? = nil
    ) async throws -> SettingsWatcher<Settings> {
        let initial = try await Settings.load(context: context, overrides: overrides)
        let watcher = SettingsWatcher(
            initial: initial,
            context: context,
            overrides: overrides,
            watchedPaths: watchedPaths,
            pollInterval: pollInterval,
            debounce: debounce,
            reloadOnSIGHUP: reloadOnSIGHUP,
            onError: onError
        )
        await watcher.beginMonitoring()
        return watcher
    }

    /// Starts background file monitoring (and optional `SIGHUP` listening) if not already active.
    public func beginMonitoring() {
        guard !isStopped, monitorTask == nil else { return }

        #if canImport(Dispatch) && os(macOS)
        if context.fileSystem is LocalFileSystem {
            installDispatchSources()
        }
        #endif

        #if canImport(Dispatch) && (canImport(Darwin) || canImport(Glibc) || canImport(Musl))
        if reloadOnSIGHUP {
            installSIGHUPSource()
        }
        #endif

        let interval = pollInterval
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                guard !Task.isCancelled, let self else { break }
                await self.checkForFileChanges()
            }
        }
    }

    /// Performs an immediate configuration reload and validation pass, atomically updating ``current``
    /// and broadcasting to ``updates()`` subscribers on success.
    ///
    /// If validation fails, ``current`` remains untouched and the error is rethrown.
    ///
    /// - Returns: Newly validated `Settings` snapshot.
    /// - Throws: ``SettingsValidationError`` or source errors when the candidate reload is invalid.
    @discardableResult
    public func reloadNow() async throws -> Settings {
        let updated = try await Settings.load(context: context, overrides: overrides)
        current = updated
        lastSnapshotDigests = Self.captureFileSnapshots(
            paths: watchedPaths,
            fileSystem: context.fileSystem
        )
        for continuation in subscribers.values {
            continuation.yield(updated)
        }
        return updated
    }

    /// Subscribes to newly validated configuration snapshots emitted on live reloads.
    ///
    /// - Returns: An `AsyncStream` yielding each newly validated `Settings` value until ``stop()`` is called.
    public func updates() -> AsyncStream<Settings> {
        let id = UUID()
        return AsyncStream { continuation in
            if isStopped {
                continuation.finish()
                return
            }
            subscribers[id] = continuation
            continuation.onTermination = { [weak self] _ in
                Task {
                    await self?.removeSubscriber(id)
                }
            }
        }
    }

    /// Stops background file and signal monitoring and finishes all active ``updates()`` streams.
    public func stop() {
        guard !isStopped else { return }
        isStopped = true
        monitorTask?.cancel()
        monitorTask = nil

        #if canImport(Dispatch) && os(macOS)
        for source in dispatchSources {
            source.cancel()
        }
        dispatchSources.removeAll()
        #endif

        #if canImport(Dispatch) && (canImport(Darwin) || canImport(Glibc) || canImport(Musl))
        sighupSource?.cancel()
        sighupSource = nil
        #endif

        for continuation in subscribers.values {
            continuation.finish()
        }
        subscribers.removeAll()
    }

    // MARK: - Internal Monitoring

    private func removeSubscriber(_ id: UUID) {
        subscribers.removeValue(forKey: id)
    }

    private func handleSignalReload() async {
        guard !isStopped else { return }
        do {
            _ = try await reloadNow()
        } catch {
            onError?(error)
        }
    }

    private func checkForFileChanges() async {
        guard !isStopped else { return }
        let currentDigests = Self.captureFileSnapshots(
            paths: watchedPaths,
            fileSystem: context.fileSystem
        )
        guard currentDigests != lastSnapshotDigests else { return }

        if debounce > .zero {
            try? await Task.sleep(for: debounce)
        }
        guard !isStopped else { return }

        do {
            _ = try await reloadNow()
        } catch {
            lastSnapshotDigests = currentDigests
            onError?(error)
        }
    }

    #if canImport(Dispatch) && os(macOS)
    private func installDispatchSources() {
        for path in watchedPaths {
            let fd = open(path, O_EVTONLY)
            guard fd >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .rename, .delete, .attrib],
                queue: DispatchQueue.global(qos: .utility)
            )
            source.setEventHandler { [weak self] in
                guard let self else { return }
                Task {
                    await self.checkForFileChanges()
                }
            }
            source.setCancelHandler {
                close(fd)
            }
            source.resume()
            dispatchSources.append(source)
        }
    }
    #endif

    #if canImport(Dispatch) && (canImport(Darwin) || canImport(Glibc) || canImport(Musl))
    private func installSIGHUPSource() {
        guard sighupSource == nil else { return }
        _ = signal(SIGHUP, SIG_IGN)
        let source = DispatchSource.makeSignalSource(
            signal: SIGHUP,
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            guard let self else { return }
            Task {
                await self.handleSignalReload()
            }
        }
        source.resume()
        sighupSource = source
    }
    #endif

    private static func resolveCandidateWatchPaths(
        explicit: [String],
        configuration: SettingsConfiguration,
        context: SettingsContext
    ) -> [String] {
        var paths: [String] = explicit
        for dotEnv in configuration.dotEnvFiles {
            paths.append(resolvePath(dotEnv, base: context.workingDirectory, home: context.homeDirectory))
        }
        for projectFile in configuration.projectConfigFiles {
            paths.append(resolvePath(projectFile, base: context.workingDirectory, home: context.homeDirectory))
        }
        if let appName = configuration.xdgAppName {
            if let xdg = context.environment["XDG_CONFIG_HOME"], !xdg.isEmpty {
                paths.append("\(xdg)/\(appName)/config.json")
            } else {
                paths.append("\(context.homeDirectory)/.config/\(appName)/config.json")
            }
        }
        var seen: Set<String> = []
        return paths.filter { seen.insert($0).inserted }
    }

    private static func resolvePath(_ path: String, base: String, home: String) -> String {
        if path == "~" { return home }
        if path.hasPrefix("~/") {
            return "\(home)/\(path.dropFirst(2))"
        }
        if path.hasPrefix("/") { return path }
        return base.hasSuffix("/") ? "\(base)\(path)" : "\(base)/\(path)"
    }

    private static func captureFileSnapshots(
        paths: [String],
        fileSystem: any FileSystem
    ) -> [String: Data?] {
        var snapshots: [String: Data?] = [:]
        for path in paths {
            if fileSystem.fileExists(atPath: path), !fileSystem.isDirectory(atPath: path) {
                snapshots[path] = try? fileSystem.readFile(atPath: path)
            } else {
                snapshots[path] = Optional<Data>.none
            }
        }
        return snapshots
    }
}
