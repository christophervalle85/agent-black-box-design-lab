// Native macOS App Sandbox feasibility probe only.
// This is not the production MCP worker or an XPC service.
// Signed with com.apple.security.app-sandbox, with no network entitlements.
// The Node harness creates a reachable loopback endpoint and an unprotected
// user-owned file *outside* this tool's sandbox container.
import Foundation
import Darwin

struct ProbeResult: Encodable {
    let hostFileDenied: Bool
    let hostFileError: String
    let networkDenied: Bool
    let networkErrorNumber: Int32
    let sandboxHomeWriteAllowed: Bool
    let sandboxHomeError: String
}

func tryHostFile(_ path: String) -> (Bool, String) {
    do {
        _ = try Data(contentsOf: URL(fileURLWithPath: path), options: .uncached)
        return (false, "read unexpectedly succeeded")
    } catch {
        let n = error as NSError
        return (true, "\(n.domain):\(n.code)")
    }
}

func tryNetwork(_ port: UInt16) -> (Bool, Int32) {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 { return (errno == EACCES || errno == EPERM, errno) }
    defer { _ = close(fd) }
    var target = sockaddr_in()
    target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    target.sin_family = sa_family_t(AF_INET)
    target.sin_port = in_port_t(port.bigEndian)
    target.sin_addr.s_addr = in_addr_t(0x7f000001).bigEndian
    let status = withUnsafePointer(to: &target) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    if status == 0 { return (false, 0) }
    let failure = errno
    // ECONNREFUSED, EHOSTUNREACH, ENETUNREACH and timeouts are inconclusive:
    // only the OS permission errors count as a demonstrated sandbox denial.
    return (failure == EACCES || failure == EPERM, failure)
}

func trySandboxHomeWrite() -> (Bool, String) {
    let path = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".agent-black-box-probe-\(UUID().uuidString).txt")
    do {
        try Data("sandbox-self-test".utf8).write(to: path, options: .withoutOverwriting)
        try FileManager.default.removeItem(at: path)
        return (true, "")
    } catch {
        let n = error as NSError
        return (false, "\(n.domain):\(n.code)")
    }
}

guard CommandLine.arguments.count == 4,
      CommandLine.arguments[1] == "--probe",
      let port = UInt16(CommandLine.arguments[3]),
      port > 0,
      CommandLine.arguments[2].hasPrefix("/") else {
    fputs("usage: blackbox-sandbox-probe --probe /absolute/host-file PORT\n", stderr)
    exit(64)
}

let file = tryHostFile(CommandLine.arguments[2])
let network = tryNetwork(port)
let home = trySandboxHomeWrite()
let result = ProbeResult(hostFileDenied: file.0, hostFileError: file.1,
                         networkDenied: network.0, networkErrorNumber: network.1,
                         sandboxHomeWriteAllowed: home.0, sandboxHomeError: home.1)
do {
    let data = try JSONEncoder().encode(result)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0a]))
} catch {
    fputs("Could not serialize native sandbox result.\n", stderr)
    exit(70)
}
