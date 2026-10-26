package com.radar.netdiag.core

import java.io.ByteArrayOutputStream

object DnsPacket {
    data class Answer(val rcode: Int, val addrs: List<String>)

    fun buildQuery(name: String, id: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)      // recursion desired
        out.write(0); out.write(1)            // QDCOUNT = 1
        repeat(6) { out.write(0) }            // AN, NS, AR
        for (label in name.split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0)
        out.write(0); out.write(1)            // QTYPE A
        out.write(0); out.write(1)            // QCLASS IN
        return out.toByteArray()
    }

    fun parse(buf: ByteArray, len: Int): Answer? {
        if (len < 12) return null
        fun u16(p: Int): Int = ((buf[p].toInt() and 0xFF) shl 8) or (buf[p + 1].toInt() and 0xFF)
        val flags = u16(2)
        if ((flags and 0x8000) == 0) return null
        val rcode = flags and 0xF
        val qd = u16(4)
        val an = u16(6)
        var pos = 12
        repeat(qd) { pos = skipName(buf, pos, len) + 4 }
        val addrs = ArrayList<String>()
        repeat(an) {
            if (pos >= len) return Answer(rcode, addrs)
            pos = skipName(buf, pos, len)
            if (pos + 10 > len) return Answer(rcode, addrs)
            val type = u16(pos)
            val rdlen = u16(pos + 8)
            pos += 10
            if (pos + rdlen > len) return Answer(rcode, addrs)
            if (type == 1 && rdlen == 4) {
                addrs.add("${buf[pos].toInt() and 0xFF}.${buf[pos + 1].toInt() and 0xFF}.${buf[pos + 2].toInt() and 0xFF}.${buf[pos + 3].toInt() and 0xFF}")
            }
            pos += rdlen
        }
        return Answer(rcode, addrs)
    }

    private fun skipName(buf: ByteArray, start: Int, len: Int): Int {
        var pos = start
        while (pos < len) {
            val l = buf[pos].toInt() and 0xFF
            if (l == 0) return pos + 1
            if ((l and 0xC0) == 0xC0) return pos + 2
            pos += l + 1
        }
        return len
    }
}
