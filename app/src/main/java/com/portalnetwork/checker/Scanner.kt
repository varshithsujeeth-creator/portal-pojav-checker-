package com.portalnetwork.checker

import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.MessageDigest
import java.util.zip.ZipFile

data class Finding(
    val path: String,
    val kind: String,          // MOD_METADATA_ANOMALY, SUSPICIOUS_NAME, ARCHIVE_CLIENT_IDENTIFIER, etc.
    val label: String,
    val confidence: String,    // "strong" | "weak"
    val sha256: String? = null
)

data class ScanReport(
    val generatedAt: String,
    val rootScanned: String,
    val filesScanned: Int,
    val findings: List<Finding>
)

/**
 * Runs scan commands through Shizuku's elevated (shell-level) process so the
 * app can read PojavLauncher's .minecraft folder even though it lives outside
 * this app's normal sandboxed storage. This mirrors what the PC .exe does by
 * walking the filesystem directly, rather than asking the user to grant a
 * folder via the system picker every time.
 *
 * Falls back gracefully with a clear error if Shizuku isn't running/granted -
 * this app never silently pretends to have scanned when it hasn't.
 */
object Scanner {

    // Common install locations for PojavLauncher's Minecraft directory.
    // Order matters: first match wins, but every path is still checked.
    val KNOWN_POJAV_PATHS = listOf(
        "/storage/emulated/0/Android/media/net.kdt.pojavlaunch/files/.minecraft",
        "/storage/emulated/0/Android/data/net.kdt.pojavlaunch/files/.minecraft",
        "/storage/emulated/0/games/PojavLauncher/.minecraft",
        "/storage/emulated/0/PojavLauncher/.minecraft"
    )

    fun isShizukuReady(): Boolean {
        return try {
            Shizuku.pingBinder() && Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED
        } catch (e: Throwable) {
            false
        }
    }

    fun requestPermissionIfNeeded() {
        if (!Shizuku.pingBinder()) return
        if (Shizuku.checkSelfPermission() != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            Shizuku.requestPermission(1001)
        }
    }

    private fun runShell(cmd: String): String {
        val process = Shizuku.newProcess(arrayOf("sh", "-c", cmd), null, null)
        val out = BufferedReader(InputStreamReader(process.inputStream)).readText()
        process.waitFor()
        return out
    }

    fun findPojavRoot(): String? {
        for (candidate in KNOWN_POJAV_PATHS) {
            val exists = runShell("[ -d \"$candidate\" ] && echo yes || echo no").trim()
            if (exists == "yes") return candidate
        }
        return null
    }

    /** Recursively list files under root, skipping SKIP_DIRS. Mirrors iter_files() in the PC tool. */
    private fun listFiles(root: String): List<String> {
        val skipClause = ClientSignatures.SKIP_DIRS.joinToString(" ") { "-not -path \"*${it.replace("\\", "/")}*\"" }
        val cmd = "find \"$root\" -type f $skipClause 2>/dev/null"
        val raw = runShell(cmd)
        return raw.lineSequence().filter { it.isNotBlank() }.toList()
    }

    private fun sha256Remote(path: String): String? {
        // sha256sum is present on virtually all modern Android /system shells (toybox).
        val out = runShell("sha256sum \"$path\" 2>/dev/null")
        val hash = out.trim().split(" ").firstOrNull()
        return if (hash?.length == 64) hash else null
    }

    /** Pull small files (jar/zip metadata reads) into a local temp copy for inspection. */
    private fun pullToLocal(remotePath: String, localFile: java.io.File): Boolean {
        return try {
            val encoded = java.util.Base64.getEncoder()
            val bytes = runShellBinary(remotePath) ?: return false
            localFile.writeBytes(bytes)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun runShellBinary(remotePath: String): ByteArray? {
        return try {
            val process = Shizuku.newProcess(arrayOf("sh", "-c", "cat \"$remotePath\""), null, null)
            val bytes = process.inputStream.readBytes()
            process.waitFor()
            bytes
        } catch (e: Exception) {
            null
        }
    }

    fun suspiciousNameIndicators(fileName: String): List<Pair<String, String>> {
        val lowered = fileName.lowercase()
        val hits = mutableListOf<Pair<String, String>>()
        for ((term, label) in ClientSignatures.STRONG_NAME_TERMS) {
            if (lowered.contains(term)) {
                hits.add(term to label)
            }
        }
        return hits
    }

    fun inspectArchive(localFile: java.io.File): List<Pair<String, String>> {
        val hits = mutableListOf<Pair<String, String>>()
        try {
            ZipFile(localFile).use { zip ->
                for (entry in zip.entries()) {
                    val name = entry.name.substringAfterLast('/')
                    if (ClientSignatures.MOD_METADATA_FILES.contains(name)) {
                        hits.add("MOD_METADATA_ANOMALY" to "Contains mod metadata file: $name")
                    }
                }
            }
        } catch (e: Exception) {
            // Not a valid zip/jar, or unreadable - skip silently like the PC tool does
            // (safe_text-style handling, never crash the whole scan on one bad file).
        }
        return hits
    }

    /**
     * Full scan pass. Returns a ScanReport, same shape/intent as the PC tool's
     * portal_network_ss_baseline.json, just serialized for the mobile UI.
     */
    fun runScan(root: String, tmpDir: java.io.File, onProgress: (String) -> Unit = {}): ScanReport {
        val files = listFiles(root)
        val findings = mutableListOf<Finding>()
        var scanned = 0

        for (path in files) {
            scanned++
            val name = path.substringAfterLast('/')
            onProgress("Scanning $name ($scanned/${files.size})")

            // 1) Name-based heuristic (weak signal, always labeled as such)
            val nameHits = suspiciousNameIndicators(name)
            for ((term, label) in nameHits) {
                findings.add(
                    Finding(
                        path = path,
                        kind = "SUSPICIOUS_NAME",
                        label = "Name contains a known cheat/client-style identifier ($term); verify the file and its origin.",
                        confidence = "weak"
                    )
                )
            }

            // 2) Archive/jar structural inspection for known mod-loader metadata
            if (name.endsWith(".jar") || name.endsWith(".zip")) {
                val tmpFile = java.io.File(tmpDir, "scan_tmp_${scanned}.jar")
                if (pullToLocal(path, tmpFile)) {
                    val archiveHits = inspectArchive(tmpFile)
                    if (archiveHits.isNotEmpty()) {
                        val hash = sha256Remote(path)
                        for ((kind, label) in archiveHits) {
                            findings.add(Finding(path, kind, label, "strong", hash))
                        }
                    }
                    tmpFile.delete()
                }
            }
        }

        return ScanReport(
            generatedAt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(java.util.Date()),
            rootScanned = root,
            filesScanned = scanned,
            findings = findings
        )
    }

    fun toJson(report: ScanReport): JSONObject {
        val obj = JSONObject()
        obj.put("generated_at", report.generatedAt)
        obj.put("root_scanned", report.rootScanned)
        obj.put("files_scanned", report.filesScanned)
        val arr = JSONArray()
        for (f in report.findings) {
            val fo = JSONObject()
            fo.put("path", f.path)
            fo.put("kind", f.kind)
            fo.put("label", f.label)
            fo.put("confidence", f.confidence)
            f.sha256?.let { fo.put("sha256", it) }
            arr.put(fo)
        }
        obj.put("findings", arr)
        return obj
    }
}
