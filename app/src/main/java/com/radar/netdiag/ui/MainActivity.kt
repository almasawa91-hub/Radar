package com.radar.netdiag.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.radar.netdiag.core.Finding
import com.radar.netdiag.core.LatencyStats
import com.radar.netdiag.core.Report
import com.radar.netdiag.core.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { RadarApp() }
    }
}

private fun sevColor(s: Severity) = when (s) {
    Severity.OK -> Color(0xFF2E7D32)
    Severity.INFO -> Color(0xFF1565C0)
    Severity.WARN -> Color(0xFFEF6C00)
    Severity.CRITICAL -> Color(0xFFC62828)
}

private fun fmt(d: Double) = String.format(Locale.US, "%.0f", d)
private fun time(ts: Long) = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(ts))

@Composable
fun RadarApp(vm: MainViewModel = viewModel()) {
    val st by vm.state.collectAsState()
    val ctx = LocalContext.current
    var cred by remember { mutableStateOf(false) }
    var bloat by remember { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { vm.run(cred, bloat) }

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        MaterialTheme {
            Surface(Modifier.fillMaxSize()) {
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    item {
                        Text("رادار", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
                        Text("تشخيص الشبكة والراوتر: أين العطل فعلًا؟")
                    }
                    item {
                        Row(Modifier.fillMaxWidth().clickable { cred = !cred }, verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Checkbox(checked = cred, onCheckedChange = { cred = it })
                            Text("اختبار كلمات المرور الافتراضية للراوتر (لشبكتي فقط)")
                        }
                    }
                    item {
                        Row(Modifier.fillMaxWidth().clickable { bloat = !bloat }, verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Checkbox(checked = bloat, onCheckedChange = { bloat = it })
                            Text("قياس تضخم المخزن (يستهلك حتى 20MB من الباقة)")
                        }
                    }
                    item {
                        Button(
                            onClick = {
                                val granted = ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                                if (granted) vm.run(cred, bloat) else launcher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
                            },
                            enabled = !st.running, modifier = Modifier.fillMaxWidth()
                        ) { Text(if (st.running) "جارٍ الفحص…" else "ابدأ التشخيص") }
                        if (st.running) {
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(progress = { st.progress }, modifier = Modifier.fillMaxWidth())
                            Text(st.stage, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    st.report?.let { r ->
                        item { SummaryCard(r) }
                        items(r.findings) { FindingCard(it) }
                        item { StagesCard(r) }
                    }
                    if (st.history.isNotEmpty()) {
                        item { Text("السجل", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold) }
                        items(st.history) { h ->
                            Row(Modifier.fillMaxWidth().clickable { vm.show(h) }.padding(vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(h.summary, Modifier.weight(1f)); Text(time(h.timestamp), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(r: Report) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(r.summary, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(time(r.timestamp), style = MaterialTheme.typography.bodySmall)
            r.downMbps?.let { Text("سرعة التحميل المقاسة: ${fmt(it)} Mbps") }
            r.bufferbloatMs?.let { Text("زيادة التأخر تحت الحمل: ${fmt(it)} ms") }
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    val c = sevColor(f.severity)
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = c.copy(alpha = 0.12f))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(f.title, color = c, fontWeight = FontWeight.Bold)
            Text("ثقة التشخيص: ${f.confidence}%", style = MaterialTheme.typography.bodySmall)
            Text(f.detail)
            f.fix?.let { Text("الحل: $it", fontWeight = FontWeight.Medium) }
        }
    }
}

@Composable
private fun StagesCard(r: Report) {
    if (r.stages.isEmpty()) return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("القياسات", fontWeight = FontWeight.Bold)
            r.stages.forEach { s -> Text(stageLine(s), style = MaterialTheme.typography.bodySmall) }
        }
    }
}

private fun stageLine(s: LatencyStats) =
    if (s.reachable) "${s.target}: متوسط ${fmt(s.avgMs)}ms، اهتزاز ${fmt(s.jitterMs)}ms، فقد ${fmt(s.lossPct)}%"
    else "${s.target}: لا استجابة"
