package com.radar.netdiag.core

enum class Severity { OK, INFO, WARN, CRITICAL }

data class LatencyStats(
    val target: String, val sent: Int, val received: Int,
    val minMs: Double, val avgMs: Double, val maxMs: Double,
    val jitterMs: Double, val medianMs: Double
) {
    val lossPct: Double get() = if (sent == 0) 0.0 else (sent - received) * 100.0 / sent
    val reachable: Boolean get() = received > 0
}

data class DnsStats(val server: String, val avgMs: Double, val failPct: Double)

data class WifiInfo(
    val rssi: Int, val channel: Int, val freqMhz: Int, val linkMbps: Int,
    val sameChannelAps: Int, val overlapAps: Int, val bestChannel: Int?
)

data class Finding(
    val id: String, val title: String, val detail: String,
    val severity: Severity, val confidence: Int, val fix: String?
)

data class Report(
    val timestamp: Long, val summary: String, val findings: List<Finding>,
    val stages: List<LatencyStats>, val bufferbloatMs: Double?, val downMbps: Double?
)

data class Measurements(
    val transport: String,
    val gateway: LatencyStats? = null,
    val internet: LatencyStats? = null,
    val systemDns: DnsStats? = null,
    val publicDns: DnsStats? = null,
    val nxdomainHijack: Boolean? = null,
    val wifi: WifiInfo? = null,
    val bufferbloatMs: Double? = null,
    val openPorts: List<Int> = emptyList(),
    val defaultCred: String? = null
)
