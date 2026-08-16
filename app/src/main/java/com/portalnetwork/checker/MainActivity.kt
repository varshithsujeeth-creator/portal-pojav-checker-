package com.portalnetwork.checker

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku

// Colors ported 1:1 from PortalHackChecker.exe
private val BgDeepest = Color(0xFF03070F)
private val BgPanel = Color(0xFF081221)
private val BgCard = Color(0xFF0D1B30)
private val BorderSoft = Color(0xFF132743)
private val TextPrimary = Color(0xFFEAF2FF)
private val TextMuted = Color(0xFF7D8BA5)
private val AccentCyan = Color(0xFF3DDCFF)
private val StatusOk = Color(0xFF5CE6A4)
private val StatusWarn = Color(0xFFFFC063)
private val StatusBad = Color(0xFFFF5F74)

class MainActivity : ComponentActivity() {

    private val permissionListener = Shizuku.OnRequestPermissionResultListener { _, grantResult ->
        shizukuGrantedState.value = grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED
    }
    private val shizukuGrantedState = mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Shizuku.addRequestPermissionResultListener(permissionListener)
        shizukuGrantedState.value = Scanner.isShizukuReady()

        setContent {
            PortalCheckerScreen(
                shizukuGranted = shizukuGrantedState.value,
                onRequestPermission = { Scanner.requestPermissionIfNeeded() },
                cacheDir = cacheDir
            )
        }
    }

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionListener)
        super.onDestroy()
    }
}

@Composable
fun PortalCheckerScreen(
    shizukuGranted: Boolean,
    onRequestPermission: () -> Unit,
    cacheDir: java.io.File
) {
    var status by remember { mutableStateOf("Idle") }
    var report by remember { mutableStateOf<ScanReport?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var showBrowser by remember { mutableStateOf(false) }
    var selectedRoot by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    MaterialTheme(
        colorScheme = darkColorScheme(
            background = BgDeepest,
            surface = BgPanel,
            primary = AccentCyan,
            onBackground = TextPrimary,
            onSurface = TextPrimary
        )
    ) {
        Surface(color = BgDeepest, modifier = Modifier.fillMaxSize()) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    "PORTAL CHECKER",
                    color = TextPrimary,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "PojavLauncher cheat-client screening",
                    color = TextMuted,
                    fontSize = 13.sp
                )

                Spacer(Modifier.height(16.dp))

                if (!shizukuGranted) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = BgCard),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Shizuku permission required", color = StatusWarn, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "This app needs Shizuku running (via ADB or root) to read PojavLauncher's .minecraft folder, the same way the PC version reads the filesystem directly.",
                                color = TextMuted,
                                fontSize = 13.sp
                            )
                            Spacer(Modifier.height(10.dp))
                            Button(onClick = onRequestPermission) {
                                Text("Grant Shizuku Permission")
                            }
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                }

                if (shizukuGranted) {
                    // --- Folder selection card ---
                    Card(
                        colors = CardDefaults.cardColors(containerColor = BgCard),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Minecraft folder", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                selectedRoot ?: "No folder selected yet.",
                                color = if (selectedRoot != null) StatusOk else TextMuted,
                                fontSize = 12.sp
                            )
                            Spacer(Modifier.height(10.dp))
                            Row {
                                Button(onClick = { showBrowser = true }) {
                                    Text(if (selectedRoot == null) "Browse & Select Folder" else "Change Folder")
                                }
                                Spacer(Modifier.width(8.dp))
                                OutlinedButton(onClick = {
                                    scope.launch {
                                        status = "Searching known PojavLauncher locations..."
                                        val root = withContext(Dispatchers.IO) { Scanner.findPojavRoot() }
                                        if (root != null) {
                                            selectedRoot = root
                                            status = "Found: $root"
                                        } else {
                                            status = "Not found in known locations - use Browse instead."
                                        }
                                    }
                                }) {
                                    Text("Auto-detect")
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    Button(
                        enabled = selectedRoot != null && !scanning,
                        onClick = {
                            val root = selectedRoot ?: return@Button
                            scanning = true
                            status = "Scanning $root ..."
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    Scanner.runScan(root, cacheDir) { progress ->
                                        status = progress
                                    }
                                }
                                report = result
                                status = "Scan complete: ${result.filesScanned} files, ${result.mods.size} mods, ${result.findings.size} findings."
                                scanning = false
                            }
                        }
                    ) {
                        Text(if (scanning) "Scanning..." else "Run Scan")
                    }

                    Spacer(Modifier.height(12.dp))
                    Text(status, color = TextMuted, fontSize = 12.sp)
                }

                Spacer(Modifier.height(16.dp))

                report?.let { r ->
                    if (r.mods.isNotEmpty()) {
                        Text(
                            "Mods installed (${r.mods.size})",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Column {
                            r.mods.forEach { mod -> ModRow(mod) }
                        }
                        Spacer(Modifier.height(16.dp))
                    }

                    Text(
                        "Findings (${r.findings.size})",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    LazyColumn(modifier = Modifier.weight(1f, fill = false)) {
                        items(r.findings) { finding ->
                            FindingRow(finding)
                            Spacer(Modifier.height(8.dp))
                        }
                    }
                }
            }
        }

        if (showBrowser) {
            FolderBrowserDialog(
                onDismiss = { showBrowser = false },
                onFolderSelected = { path ->
                    selectedRoot = path
                    showBrowser = false
                }
            )
        }
    }
}

@Composable
fun FolderBrowserDialog(
    onDismiss: () -> Unit,
    onFolderSelected: (String) -> Unit
) {
    var currentPath by remember { mutableStateOf("/storage/emulated/0") }
    var entries by remember { mutableStateOf<List<DirEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(currentPath) {
        loading = true
        entries = withContext(Dispatchers.IO) { Scanner.listDir(currentPath) }
        loading = false
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgPanel,
        title = {
            Column {
                Text("Select Folder", color = TextPrimary, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(currentPath, color = AccentCyan, fontSize = 11.sp)
            }
        },
        text = {
            Column(modifier = Modifier.height(400.dp)) {
                if (currentPath != "/") {
                    Text(
                        ".. (up one level)",
                        color = TextMuted,
                        fontSize = 13.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                currentPath = currentPath.substringBeforeLast('/', "/").ifBlank { "/" }
                            }
                            .padding(vertical = 8.dp)
                    )
                }
                if (loading) {
                    Text("Loading...", color = TextMuted, fontSize = 12.sp, modifier = Modifier.padding(vertical = 8.dp))
                } else {
                    LazyColumn(modifier = Modifier.weight(1f)) {
                        items(entries.filter { it.isDir }) { entry ->
                            Text(
                                "\uD83D\uDCC1 ${entry.name}",
                                color = TextPrimary,
                                fontSize = 13.sp,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { currentPath = entry.fullPath }
                                    .padding(vertical = 8.dp)
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = { onFolderSelected(currentPath) }) {
                Text("Select This Folder")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun ModRow(mod: ModInfo) {
    val (verdictColor, verdictLabel) = when (mod.verdict) {
        "VERIFIED" -> StatusOk to "VERIFIED"
        "SUSPICIOUS" -> StatusBad to "SUSPICIOUS"
        "OBFUSCATED" -> StatusWarn to "OBFUSCATED"
        else -> TextMuted to "UNKNOWN"
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = BgCard),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(mod.name, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    Text("v${mod.version} · ${mod.loader}", color = TextMuted, fontSize = 11.sp)
                }
                Box(
                    modifier = Modifier
                        .background(verdictColor.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(verdictLabel, color = verdictColor, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
            if (mod.sourceProject != null) {
                Spacer(Modifier.height(4.dp))
                Text("Matched Modrinth project: ${mod.sourceProject}", color = StatusOk, fontSize = 11.sp)
            }
            if (mod.verdictReasons.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                mod.verdictReasons.forEach { reason ->
                    Text("• $reason", color = TextMuted, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
fun FindingRow(finding: Finding) {
    val color = if (finding.confidence == "strong") StatusBad else StatusWarn
    Card(
        colors = CardDefaults.cardColors(containerColor = BgCard),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(color, shape = androidx.compose.foundation.shape.CircleShape)
                )
                Spacer(Modifier.width(8.dp))
                Text(finding.kind, color = color, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(4.dp))
            Text(finding.path, color = TextMuted, fontSize = 11.sp)
            Spacer(Modifier.height(4.dp))
            Text(finding.label, color = TextPrimary, fontSize = 13.sp)
        }
    }
}
