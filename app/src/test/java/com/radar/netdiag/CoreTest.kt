package com.radar.netdiag

import com.radar.netdiag.core.*
import org.junit.Assert.*
import org.junit.Test

class CoreTest {
    @Test fun statsComputeLossJitterMedian() {
        val s = Stats.of("x", 4, listOf(10.0, 20.0, 10.0))
        assertEquals(3, s.received); assertEquals(25.0, s.lossPct, 0.01)
        assertEquals(10.0, s.jitterMs, 0.01); assertEquals(10.0, s.medianMs, 0.01)
    }

    @Test fun channelMapping() {
        assertEquals(1, Channels.channel(2412)); assertEquals(6, Channels.channel(2437))
        assertEquals(14, Channels.channel(2484)); assertEquals(36, Channels.channel(5180))
        assertEquals(1, Channels.channel(5955))
    }

    @Test fun channelCongestion() {
        val scans = listOf(2437 to -50, 2437 to -60, 2437 to -65, 2437 to -70, 2412 to -60)
        val l = Channels.analyse(2437, scans)
        assertEquals(3, l.same); assertEquals(1, l.overlap)
    }

    @Test fun dnsQueryRoundTrip() {
        val q = DnsPacket.buildQuery("a.example.com", 0x1234)
        val resp = q.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte(); it[7] = 1 } +
            byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
        val a = DnsPacket.parse(resp, resp.size)!!
        assertEquals(0, a.rcode); assertEquals(listOf("1.2.3.4"), a.addrs)
    }

    @Test fun dnsNxdomainParsed() {
        val q = DnsPacket.buildQuery("a.example.com", 7)
        val resp = q.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x83.toByte() }
        val a = DnsPacket.parse(resp, resp.size)!!
        assertEquals(3, a.rcode); assertTrue(a.addrs.isEmpty())
    }

    @Test fun ispDownWhenRouterOkButInternetDead() {
        val m = Measurements("wifi",
            gateway = Stats.of("gw", 10, List(10) { 4.0 }),
            internet = Stats.of("i", 10, emptyList()))
        assertEquals("isp_down", Rules.evaluate(m).first().id)
    }

    @Test fun bufferbloatCritical() {
        val ok = Stats.of("i", 10, List(10) { 20.0 })
        val f = Rules.evaluate(Measurements("wifi", gateway = Stats.of("gw", 10, List(10) { 3.0 }), internet = ok, bufferbloatMs = 350.0))
        assertEquals(Severity.CRITICAL, f.first { it.id == "bufferbloat" }.severity)
    }

    @Test fun hijackDetected() {
        val ok = Stats.of("i", 10, List(10) { 20.0 })
        val f = Rules.evaluate(Measurements("wifi", internet = ok, nxdomainHijack = true))
        assertTrue(f.any { it.id == "dns_hijack" })
    }

    @Test fun healthyNetworkIsOk() {
        val ok = Stats.of("i", 10, List(10) { 20.0 })
        val f = Rules.evaluate(Measurements("wifi", gateway = Stats.of("gw", 10, List(10) { 3.0 }), internet = ok))
        assertEquals("ok", f.first().id)
    }
}
