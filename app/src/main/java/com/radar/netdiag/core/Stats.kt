package com.radar.netdiag.core

import kotlin.math.abs

object Stats {
    fun of(target: String, sent: Int, samples: List<Double>): LatencyStats {
        if (samples.isEmpty()) return LatencyStats(target, sent, 0, 0.0, 0.0, 0.0, 0.0, 0.0)
        val s = samples.sorted()
        val med = if (s.size % 2 == 1) s[s.size / 2] else (s[s.size / 2 - 1] + s[s.size / 2]) / 2
        var jit = 0.0
        if (samples.size > 1) {
            for (i in 1 until samples.size) jit += abs(samples[i] - samples[i - 1])
            jit /= (samples.size - 1)
        }
        return LatencyStats(target, sent, samples.size, s.first(), samples.average(), s.last(), jit, med)
    }
}

object Channels {
    data class Load(val same: Int, val overlap: Int, val best: Int?)

    fun channel(f: Int): Int = when {
        f == 2484 -> 14
        f in 2400..2483 -> (f - 2407) / 5
        f in 5000..5924 -> (f - 5000) / 5
        f >= 5925 -> (f - 5950) / 5
        else -> 0
    }

    /** scans: pairs of (frequencyMhz, rssiDbm). The connected AP itself is included in scans. */
    fun analyse(ownFreq: Int, scans: List<Pair<Int, Int>>): Load {
        val strong = scans.filter { it.second > -80 }
        val ownCh = channel(ownFreq)
        val same = maxOf(0, strong.count { it.first == ownFreq } - 1)
        val is24 = ownFreq < 3000
        val overlap = if (is24) strong.count {
            it.first < 3000 && channel(it.first) != ownCh && abs(channel(it.first) - ownCh) < 5
        } else 0
        val best = if (is24) listOf(1, 6, 11).minByOrNull { cand ->
            strong.count { it.first < 3000 && abs(channel(it.first) - cand) < 5 } - (if (cand == ownCh) 1 else 0)
        } else null
        return Load(same, overlap, best)
    }
}
