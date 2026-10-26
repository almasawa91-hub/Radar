package com.radar.netdiag.core

import android.util.Base64
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

object Probe {
    /** زمن اتصال TCP. الرفض السريع (RST) يعني أن الجهاز حيّ ويُحتسب. */
    fun tcp(host: String, port: Int, count: Int, timeoutMs: Int, label: String = host): LatencyStats {
        val addr = try { InetAddress.getByName(host) } catch (e: Exception) { return Stats.of(label, count, emptyList()) }
        val samples = ArrayList<Double>()
        repeat(count) {
            val t0 = System.nanoTime()
            var ok = false
            try {
                Socket().use { it.connect(InetSocketAddress(addr, port), timeoutMs) }
                ok = true
            } catch (e: ConnectException) {
                ok = e.message?.contains("refused", ignoreCase = true) == true
            } catch (e: Exception) {
            }
            if (ok) samples.add((System.nanoTime() - t0) / 1e6)
            try { Thread.sleep(50) } catch (e: InterruptedException) { }
        }
        return Stats.of(label, count, samples)
    }

    fun gateway(host: String): LatencyStats {
        for (p in intArrayOf(80, 443, 53, 22, 23, 8080)) {
            if (tcp(host, p, 2, 800, "الراوتر").reachable) return tcp(host, p, 12, 1000, "الراوتر")
        }
        return Stats.of("الراوتر", 12, emptyList())
    }

    fun openPorts(host: String, ports: List<Int>): List<Int> {
        val ex = Executors.newFixedThreadPool(ports.size)
        try {
            val fs = ports.map { p ->
                ex.submit(Callable {
                    try { Socket().use { it.connect(InetSocketAddress(host, p), 700) }; true } catch (e: Exception) { false }
                })
            }
            return ports.filterIndexed { i, _ -> fs[i].get() }
        } finally { ex.shutdownNow() }
    }
}

object DnsClient {
    data class Result(val rcode: Int, val addrs: List<String>, val ms: Double)

    fun query(server: String, name: String, timeoutMs: Int = 2000): Result? {
        return try {
            val id = Random.nextInt(0x10000)
            val q = DnsPacket.buildQuery(name, id)
            DatagramSocket().use { s ->
                s.soTimeout = timeoutMs
                val addr = InetAddress.getByName(server)
                val t0 = System.nanoTime()
                s.send(DatagramPacket(q, q.size, addr, 53))
                val buf = ByteArray(1500)
                val p = DatagramPacket(buf, buf.size)
                s.receive(p)
                val ms = (System.nanoTime() - t0) / 1e6
                val rid = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
                if (rid != id) null else DnsPacket.parse(buf, p.length)?.let { Result(it.rcode, it.addrs, ms) }
            }
        } catch (e: Exception) { null }
    }
}

object Bloat {
    data class Result(val idleMs: Double, val loadedMs: Double, val downMbps: Double)

    fun measure(target: String = "1.1.1.1", maxBytes: Long = 20_000_000L): Result? {
        val idle = Probe.tcp(target, 443, 8, 1500)
        if (!idle.reachable) return null
        val stop = AtomicBoolean(false)
        val bytes = AtomicLong(0)
        val threads = (1..2).map {
            Thread {
                while (!stop.get()) {
                    try {
                        val c = URL("https://speed.cloudflare.com/__down?bytes=100000000").openConnection() as HttpURLConnection
                        c.connectTimeout = 3000; c.readTimeout = 3000
                        c.inputStream.use { ins ->
                            val b = ByteArray(32768)
                            while (!stop.get()) {
                                val n = ins.read(b)
                                if (n < 0) break
                                if (bytes.addAndGet(n.toLong()) >= maxBytes) stop.set(true)
                            }
                        }
                        c.disconnect()
                    } catch (e: Exception) {
                        try { Thread.sleep(200) } catch (e2: InterruptedException) { }
                    }
                }
            }.also { it.start() }
        }
        try {
            Thread.sleep(1500)
            val t0 = System.nanoTime(); val b0 = bytes.get()
            val loaded = Probe.tcp(target, 443, 15, 3000)
            val dt = (System.nanoTime() - t0) / 1e9
            val mbps = (bytes.get() - b0) * 8 / 1e6 / dt
            if (bytes.get() == 0L) return null   // فشل التحميل: لا قياس موثوق
            val loadedMs = if (loaded.reachable) loaded.medianMs else 3000.0
            return Result(idle.medianMs, loadedMs, mbps)
        } finally {
            stop.set(true)
            threads.forEach { try { it.join(1500) } catch (e: InterruptedException) { } }
        }
    }
}

object RouterAudit {
    private val creds = listOf("admin" to "admin", "admin" to "1234", "admin" to "password", "admin" to "",
        "root" to "admin", "user" to "user", "admin" to "12345", "root" to "root")

    /** يعمل فقط مع الراوترات التي تستخدم HTTP Basic Auth، ويُستدعى فقط بموافقة المستخدم على شبكته. */
    fun findDefaultCredential(host: String): String? {
        fun code(auth: String?): Int = try {
            val c = URL("http://$host/").openConnection() as HttpURLConnection
            c.connectTimeout = 2000; c.readTimeout = 2000; c.instanceFollowRedirects = false
            if (auth != null) c.setRequestProperty("Authorization", "Basic $auth")
            val r = c.responseCode
            c.disconnect()
            r
        } catch (e: Exception) { -1 }
        if (code(null) != 401) return null
        for ((u, p) in creds) {
            val a = Base64.encodeToString("$u:$p".toByteArray(), Base64.NO_WRAP)
            if (code(a) == 200) return "$u:${if (p.isEmpty()) "(فارغة)" else p}"
        }
        return null
    }
}
