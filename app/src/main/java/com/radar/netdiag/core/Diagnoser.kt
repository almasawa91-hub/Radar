package com.radar.netdiag.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import java.net.Inet4Address
import kotlin.random.Random

data class Options(val credCheck: Boolean, val bloat: Boolean)

class Diagnoser(private val ctx: Context) {

    fun run(opts: Options, progress: (String, Float) -> Unit): Report {
        val stages = mutableListOf<LatencyStats>()
        progress("قراءة حالة الشبكة", 0.05f)
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val net = cm.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val transport = when {
            caps == null -> "none"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
            else -> "other"
        }
        if (transport == "none") return finish(Measurements("none"), stages, null)

        val lp = net?.let { cm.getLinkProperties(it) }
        val gateway = lp?.routes?.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress
        val dnsServer = lp?.dnsServers?.firstOrNull { it is Inet4Address }?.hostAddress
        val local = transport != "cell"

        var gwStats: LatencyStats? = null
        if (gateway != null && local) {
            progress("اختبار الراوتر", 0.12f)
            gwStats = Probe.gateway(gateway); stages += gwStats
        }

        progress("اختبار الإنترنت", 0.25f)
        var inet = Probe.tcp("1.1.1.1", 443, 10, 1500, "الإنترنت (1.1.1.1)")
        if (!inet.reachable) inet = Probe.tcp("8.8.8.8", 443, 6, 1500, "الإنترنت (8.8.8.8)")
        stages += inet

        progress("اختبار DNS", 0.4f)
        val sys = dnsServer?.let { dnsTest(it) }
        val pub = dnsTest("1.1.1.1")
        val hijack = if (sys != null) (sys.second && !pub.second) else null

        progress("تحليل Wi-Fi", 0.55f)
        val wifi = if (transport == "wifi") wifiInfo() else null

        var bloat: Double? = null
        var mbps: Double? = null
        if (opts.bloat && local && inet.reachable) {
            progress("قياس تضخم المخزن (حتى 20MB)", 0.65f)
            Bloat.measure()?.let { bloat = (it.loadedMs - it.idleMs).coerceAtLeast(0.0); mbps = it.downMbps }
        }

        var ports = emptyList<Int>()
        var cred: String? = null
        if (gateway != null && local) {
            progress("فحص إعدادات الراوتر", 0.88f)
            ports = Probe.openPorts(gateway, listOf(21, 22, 23, 80, 443, 8080, 7547))
            if (opts.credCheck && 80 in ports) cred = RouterAudit.findDefaultCredential(gateway)
        }

        val m = Measurements(transport, gwStats, inet, sys?.first, pub.first, hijack, wifi, bloat, ports, cred)
        return finish(m, stages, mbps)
    }

    private fun finish(m: Measurements, stages: List<LatencyStats>, mbps: Double?): Report {
        val findings = Rules.evaluate(m)
        val top = findings.first()
        val summary = if (top.severity >= Severity.WARN) top.title else "الشبكة تبدو سليمة"
        return Report(System.currentTimeMillis(), summary, findings, stages, m.bufferbloatMs, mbps)
    }

    /** استعلامات لأسماء عشوائية تحت example.com: نقيس زمن الاستجابة غير المخزَّن ونكشف إعادة التوجيه. */
    private fun dnsTest(server: String): Pair<DnsStats, Boolean> {
        var ok = 0; var sum = 0.0; var hijack = false
        val total = 5
        repeat(total) {
            val r = DnsClient.query(server, "radar-${Random.nextInt(1_000_000)}.example.com")
            if (r != null && (r.rcode == 0 || r.rcode == 3)) {
                ok++; sum += r.ms
                if (r.rcode == 0 && r.addrs.isNotEmpty()) hijack = true
            }
        }
        return DnsStats(server, if (ok > 0) sum / ok else 0.0, (total - ok) * 100.0 / total) to hijack
    }

    @Suppress("DEPRECATION")
    private fun wifiInfo(): WifiInfo? {
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null
        val ci = wm.connectionInfo ?: return null
        val freq = ci.frequency
        if (freq <= 0) return null
        val scans = try { wm.scanResults.map { it.frequency to it.level } } catch (e: SecurityException) { emptyList() }
        val load = if (scans.isEmpty()) Channels.Load(0, 0, null) else Channels.analyse(freq, scans)
        return WifiInfo(ci.rssi, Channels.channel(freq), freq, ci.linkSpeed, load.same, load.overlap, load.best)
    }
}
