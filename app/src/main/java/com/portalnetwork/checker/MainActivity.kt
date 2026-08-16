package com.portalnetwork.checker

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
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
                }

                Spacer(Modifier.height(16.dp))

                Button(
                    enabled = shizukuGranted && !scanning,
                    onClick = {
                        scanning = true
                        status = "Locating PojavLauncher..."
                        scope.launch {
                            val root = withContext(Dispatchers.IO) { Scanner.findPojavRoot() }
                            if (root == null) {
                                status = "PojavLauncher .minecraft folder not found in known locations."
                                scanning = false
                                return@launch
                            }
                            status = "Scanning $root ..."
                            val result = withContext(Dispatchers.IO) {
                                Scanner.runScan(root, cacheDir) { progress ->
                                    status = progress
                                }
                            }
                            report = result
                            status = "Scan complete: ${result.filesScanned} files, ${result.findings.size} findings."
                            scanning = false
                        }
                    }
                ) {
                    Text(if (scanning) "Scanning..." else "Run Scan")
                }

                Spacer(Modifier.height(12.dp))
                Text(status, color = TextMuted, fontSize = 12.sp)

                Spacer(Modifier.height(16.dp))

                report?.let { r ->
                    Text(
                        "Findings (${r.findings.size})",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    LazyColumn {
                        items(r.findings) { finding ->
                            FindingRow(finding)
                            Spacer(Modifier.height(8.dp))
                        }
                    }
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
