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
    val findings: List<Finding>,
    val mods: List<ModInfo> = emptyList()
)

data class ModInfo(
    val fileName: String,
    val path: String,
    val name: String,
    val version: String,
    val loader: String   // "fabric" | "forge" | "quilt" | "unknown"
)

data class DirEntry(val name: String, val fullPath: String, val isDir: Boolean)

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

    /**
     * Shizuku.newProcess() is marked private in the API artifact even though the
     * method still exists at runtime, so it's invoked via reflection here. This is
     * the standard workaround used by apps built against modern Shizuku API versions.
     */
    private fun shizukuNewProcess(cmd: Array<String>, env: Array<String>?, dir: String?): Process {
        val method = Shizuku::class.java.getDeclaredMethod(
            "newProcess",
            Array<String>::class.java,
            Array<String>::class.java,
            String::class.java
        )
        method.isAccessible = true
        return method.invoke(null, cmd, env, dir) as Process
    }

    private fun runShell(cmd: String): String {
        val process = shizukuNewProcess(arrayOf("sh", "-c", cmd), null, null)
        val out = BufferedReader(InputStreamReader(process.inputStream)).readText()
        process.waitFor()
        return out
    }

    /**
     * Lists immediate children of a directory via Shizuku's shell access, so the
     * user can browse and pick their exact PojavLauncher/.minecraft path instead
     * of relying on a fixed list of known install locations.
     */
    fun listDir(path: String): List<DirEntry> {
        val safePath = path.ifBlank { "/storage/emulated/0" }
        val cmd = "find \"$safePath\" -mindepth 1 -maxdepth 1 2>/dev/null | while IFS= read -r f; do " +
                "if [ -d \"\$f\" ]; then echo \"D:\$f\"; else echo \"F:\$f\"; fi; done"
        val raw = runShell(cmd)
        return raw.lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val isDir = line.startsWith("D:")
                val fullPath = line.removePrefix("D:").removePrefix("F:")
                if (fullPath.isBlank()) return@mapNotNull null
                DirEntry(name = fullPath.substringAfterLast('/'), fullPath = fullPath, isDir = isDir)
            }
            .sortedWith(compareBy({ !it.isDir }, { it.name.lowercase() }))
            .toList()
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
            val process = shizukuNewProcess(arrayOf("sh", "-c", "cat \"$remotePath\""), null, null)
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
     * Reads the mod-loader metadata file (fabric.mod.json / quilt.mod.json / mods.toml /
     * mcmod.info) out of a jar to get a human-readable mod name + version for display,
     * separate from the cheat-detection heuristics.
     */
    fun readModInfo(localFile: java.io.File, fileName: String, remotePath: String): ModInfo {
        try {
            ZipFile(localFile).use { zip ->
                zip.getEntry("fabric.mod.json")?.let { entry ->
                    val text = zip.getInputStream(entry).bufferedReader().readText()
                    val json = JSONObject(text)
                    return ModInfo(
                        fileName = fileName,
                        path = remotePath,
                        name = json.optString("name", json.optString("id", fileName)),
                        version = json.optString("version", "unknown"),
                        loader = "fabric"
                    )
                }
                zip.getEntry("quilt.mod.json")?.let { entry ->
                    val text = zip.getInputStream(entry).bufferedReader().readText()
                    val json = JSONObject(text)
                    val loaderObj = json.optJSONObject("quilt_loader")
                    return ModInfo(
                        fileName = fileName,
                        path = remotePath,
                        name = loaderObj?.optString("name", loaderObj.optString("id", fileName)) ?: fileName,
                        version = loaderObj?.optString("version", "unknown") ?: "unknown",
                        loader = "quilt"
                    )
                }
                (zip.getEntry("META-INF/mods.toml") ?: zip.getEntry("META-INF/neoforge.mods.toml"))?.let { entry ->
                    val text = zip.getInputStream(entry).bufferedReader().readText()
                    val name = Regex("displayName\\s*=\\s*\"([^\"]*)\"").find(text)?.groupValues?.get(1)
                    val version = Regex("version\\s*=\\s*\"([^\"]*)\"").find(text)?.groupValues?.get(1)
                    return ModInfo(
                        fileName = fileName,
                        path = remotePath,
                        name = name ?: fileName,
                        version = version ?: "unknown",
                        loader = "forge"
                    )
                }
                zip.getEntry("mcmod.info")?.let { entry ->
                    val text = zip.getInputStream(entry).bufferedReader().readText()
                    val arr = JSONArray(text)
                    if (arr.length() > 0) {
                        val obj = arr.getJSONObject(0)
                        return ModInfo(
                            fileName = fileName,
                            path = remotePath,
                            name = obj.optString("name", fileName),
                            version = obj.optString("version", "unknown"),
                            loader = "forge"
                        )
                    }
                }
            }
        } catch (e: Exception) {
            // Fall through to unknown below - unreadable metadata never crashes the scan.
        }
        return ModInfo(fileName = fileName, path = remotePath, name = fileName, version = "unknown", loader = "unknown")
    }

    /**
     * Scans the text content of every entry inside a jar/zip (class files, resource
     * files, configs) for known cheat/client identifier strings - catches hits that
     * a filename-only or metadata-only check would miss.
     */
    fun scanArchiveContentForCheatStrings(localFile: java.io.File): List<Pair<String, String>> {
        val hits = mutableListOf<Pair<String, String>>()
        val seenTerms = mutableSetOf<String>()
        try {
            ZipFile(localFile).use { zip ->
                for (entry in zip.entries()) {
                    if (entry.isDirectory) continue
                    if (entry.size > 5_000_000) continue // skip huge entries (e.g. embedded assets)
                    val bytes = try {
                        zip.getInputStream(entry).readBytes()
                    } catch (e: Exception) {
                        continue
                    }
                    // Read as latin1 so every byte maps to a char - cheap way to find
                    // ASCII strings embedded in compiled .class files too.
                    val text = String(bytes, Charsets.ISO_8859_1).lowercase()
                    for ((term, label) in ClientSignatures.STRONG_NAME_TERMS) {
                        if (term in seenTerms) continue
                        if (text.contains(term)) {
                            seenTerms.add(term)
                            hits.add(term to label)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Not a valid/readable zip - skip silently, same handling as inspectArchive.
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
        val mods = mutableListOf<ModInfo>()
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

            // 2) Archive/jar structural inspection for known mod-loader metadata,
            //    mod name/version extraction, and in-content cheat string scanning.
            if (name.endsWith(".jar") || name.endsWith(".zip")) {
                val tmpFile = java.io.File(tmpDir, "scan_tmp_${scanned}.jar")
                if (pullToLocal(path, tmpFile)) {
                    if (name.endsWith(".jar") && path.contains("/mods/")) {
                        mods.add(readModInfo(tmpFile, name, path))
                    }

                    val archiveHits = inspectArchive(tmpFile)
                    val contentHits = scanArchiveContentForCheatStrings(tmpFile)
                    val allHits = archiveHits + contentHits.map { (term, label) ->
                        "CHEAT_STRING_IN_CONTENT" to "Cheat/client identifier found inside file contents ($term): $label"
                    }
                    if (allHits.isNotEmpty()) {
                        val hash = sha256Remote(path)
                        for ((kind, label) in allHits) {
                            val confidence = if (kind == "CHEAT_STRING_IN_CONTENT") "weak" else "strong"
                            findings.add(Finding(path, kind, label, confidence, hash))
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
            findings = findings,
            mods = mods
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
