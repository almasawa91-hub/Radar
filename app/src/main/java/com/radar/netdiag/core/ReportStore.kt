package com.radar.netdiag.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class ReportStore(ctx: Context) {
    private val dir = File(ctx.filesDir, "reports").apply { mkdirs() }

    fun save(r: Report) {
        File(dir, "${r.timestamp}.json").writeText(toJson(r).toString())
        dir.listFiles()?.sortedByDescending { it.name }?.drop(30)?.forEach { it.delete() }
    }

    fun list(): List<Report> =
        dir.listFiles()?.filter { it.extension == "json" }?.sortedByDescending { it.name }
            ?.mapNotNull { runCatching { fromJson(JSONObject(it.readText())) }.getOrNull() }.orEmpty()

    private fun toJson(r: Report) = JSONObject().apply {
        put("ts", r.timestamp); put("summary", r.summary)
        putOpt("bloat", r.bufferbloatMs); putOpt("mbps", r.downMbps)
        put("findings", JSONArray().apply {
            r.findings.forEach { f ->
                put(JSONObject().put("id", f.id).put("title", f.title).put("detail", f.detail)
                    .put("sev", f.severity.name).put("conf", f.confidence).putOpt("fix", f.fix))
            }
        })
        put("stages", JSONArray().apply {
            r.stages.forEach { s ->
                put(JSONObject().put("t", s.target).put("sent", s.sent).put("rcv", s.received).put("min", s.minMs)
                    .put("avg", s.avgMs).put("max", s.maxMs).put("jit", s.jitterMs).put("med", s.medianMs))
            }
        })
    }

    private fun fromJson(o: JSONObject): Report {
        val fa = o.getJSONArray("findings"); val sa = o.getJSONArray("stages")
        return Report(
            o.getLong("ts"), o.getString("summary"),
            (0 until fa.length()).map { i -> fa.getJSONObject(i).let {
                Finding(it.getString("id"), it.getString("title"), it.getString("detail"),
                    Severity.valueOf(it.getString("sev")), it.getInt("conf"), if (it.has("fix")) it.getString("fix") else null) } },
            (0 until sa.length()).map { i -> sa.getJSONObject(i).let {
                LatencyStats(it.getString("t"), it.getInt("sent"), it.getInt("rcv"), it.getDouble("min"),
                    it.getDouble("avg"), it.getDouble("max"), it.getDouble("jit"), it.getDouble("med")) } },
            if (o.has("bloat")) o.getDouble("bloat") else null,
            if (o.has("mbps")) o.getDouble("mbps") else null
        )
    }
}
