package com.radar.netdiag.core

import java.util.Locale

object Rules {
    private fun n(d: Double) = String.format(Locale.US, "%.0f", d)

    fun evaluate(m: Measurements): List<Finding> {
        if (m.transport == "none") {
            return listOf(Finding("no_net", "لا يوجد اتصال بالشبكة", "الجهاز غير متصل بأي شبكة.",
                Severity.CRITICAL, 99, "فعّل Wi-Fi أو بيانات الجوال ثم أعد الفحص."))
        }
        val f = mutableListOf<Finding>()
        val inet = m.internet
        val inetOk = inet?.reachable == true
        // بعض الراوترات لا ترد على TCP؛ لا نعتبر ذلك عطلًا إن كان الإنترنت يعمل.
        val gw = m.gateway?.takeIf { it.reachable || !inetOk }
        val gwOk = gw?.reachable == true
        val onWifi = m.transport == "wifi"

        if (gw != null && !gwOk) {
            f += Finding("gw_down", "الراوتر لا يستجيب ولا يوجد إنترنت",
                "لم يرد الراوتر على أي منفذ تم اختباره والإنترنت غير متاح. قد يكون الراوتر متوقفًا أو الاتصال اللاسلكي منقطعًا (احتمال أن الراوتر يحجب الاختبار وارد).",
                Severity.CRITICAL, 65, "أعد تشغيل الراوتر وقرّب الهاتف منه ثم أعد الفحص.")
        }
        if (gw != null && gwOk && (gw.lossPct >= 5 || gw.avgMs > 25 || gw.jitterMs > 15)) {
            val weak = (m.wifi?.rssi ?: 0) < -75 && m.wifi != null
            f += Finding("local_link", "مشكلة في الرابط بين هاتفك والراوتر",
                "تأخر الراوتر ${n(gw.avgMs)}ms، اهتزاز ${n(gw.jitterMs)}ms، فقد ${n(gw.lossPct)}%. هذه القيم يجب أن تكون شبه معدومة على شبكة محلية سليمة.",
                Severity.WARN, if (weak) 85 else 60,
                if (weak) "الإشارة ضعيفة: اقترب من الراوتر أو استخدم نطاق 5GHz أو مقوّي إشارة."
                else "جرّب تغيير قناة الراوتر أو إعادة تشغيله، وتحقق من ازدحام القناة.")
        }
        if (inet != null && !inetOk && gwOk) {
            f += Finding("isp_down", "الراوتر سليم لكن الإنترنت منقطع خلفه",
                "الراوتر يستجيب محليًا بينما لا يمكن الوصول إلى خوادم الإنترنت.",
                Severity.CRITICAL, 85, "افحص أضواء WAN/DSL في الراوتر وكبل الخط، ثم تواصل مع المزود.")
        }
        if (gwOk && inetOk && gw != null && inet != null && inet.avgMs - gw.avgMs > 150) {
            f += Finding("isp_latency", "تأخر مرتفع بعد الراوتر (شبكة 4G أو المزود)",
                "الفرق بين تأخر الإنترنت (${n(inet.avgMs)}ms) والراوتر (${n(gw.avgMs)}ms) كبير، والرابط المحلي سليم.",
                Severity.WARN, 70, "المشكلة غالبًا في خط المزود أو ازدحام شبكته. أعد الفحص في وقت آخر وتواصل مع المزود إن استمر.")
        }
        if (inet != null && inetOk && inet.lossPct >= 10 && (gw == null || gw.lossPct < 3)) {
            f += Finding("isp_loss", "فقد حزم في طريق الإنترنت",
                "فقد ${n(inet.lossPct)}% من الاتصالات نحو الإنترنت بينما الرابط المحلي سليم.",
                Severity.WARN, 70, "غالبًا من المزود أو خط الراوتر.")
        }

        val sys = m.systemDns
        val pub = m.publicDns
        if (sys != null && inetOk && sys.failPct >= 40) {
            f += Finding("dns_fail", "خادم DNS الحالي لا يستجيب بشكل موثوق",
                "فشل ${n(sys.failPct)}% من استعلامات DNS إلى ${sys.server} بينما الإنترنت يعمل.",
                Severity.CRITICAL, 85, "غيّر DNS إلى 1.1.1.1 أو 8.8.8.8 (الإعدادات > DNS الخاص).")
        } else if (sys != null && pub != null && sys.avgMs > 120 && sys.avgMs > pub.avgMs * 2.5) {
            f += Finding("dns_slow", "خادم DNS بطيء",
                "متوسط الاستجابة ${n(sys.avgMs)}ms مقابل ${n(pub.avgMs)}ms لخادم عام. يظهر ذلك كبطء في فتح المواقع.",
                Severity.WARN, 75, "جرّب DNS عامًا مثل 1.1.1.1 أو 8.8.8.8.")
        }
        if (m.nxdomainHijack == true) {
            f += Finding("dns_hijack", "إعادة توجيه الأسماء غير الموجودة",
                "الخادم الحالي يعيد عنوانًا لاسم غير موجود بينما الخادم العام يرجع «غير موجود». هذا سلوك إعلانات/تلاعب من المزود أو الراوتر.",
                Severity.WARN, 80, "استخدم DNS عامًا أو DNS-over-TLS (DNS الخاص).")
        }

        val w = m.wifi
        if (onWifi && w != null) {
            if (w.rssi < -80) {
                f += Finding("wifi_weak", "إشارة Wi-Fi ضعيفة جدًا", "قوة الإشارة ${w.rssi}dBm.", Severity.CRITICAL, 80, "اقترب من الراوتر أو أضف مقوّي إشارة.")
            } else if (w.rssi < -70) {
                f += Finding("wifi_weak", "إشارة Wi-Fi متوسطة الضعف", "قوة الإشارة ${w.rssi}dBm.", Severity.WARN, 70, "اقترب من الراوتر أو استخدم 5GHz إن أمكن.")
            }
            if (w.sameChannelAps >= 3 || w.overlapAps >= 5) {
                val tip = if (w.freqMhz < 3000 && w.bestChannel != null && w.bestChannel != w.channel)
                    "انقل الراوتر إلى القناة ${w.bestChannel} (من 1/6/11) أو انتقل إلى 5GHz."
                else "جرّب نطاق 5GHz أو غيّر القناة من إعدادات الراوتر."
                f += Finding("wifi_congestion", "ازدحام في قناة Wi-Fi",
                    "القناة ${w.channel}: ${w.sameChannelAps} شبكات قوية على نفس القناة و${w.overlapAps} متداخلة.",
                    Severity.WARN, 65, tip)
            }
        }

        val b = m.bufferbloatMs
        if (b != null && b >= 100) {
            f += Finding("bufferbloat", "تضخم المخزن (Bufferbloat)",
                "يرتفع التأخر بمقدار ${n(b)}ms أثناء التحميل. يسبب تقطع المكالمات والألعاب أثناء التنزيل.",
                if (b >= 300) Severity.CRITICAL else Severity.WARN, 80,
                "فعّل SQM/QoS (Smart Queue) في الراوتر وحدّد السرعة بنحو 90% من السرعة الفعلية.")
        }

        if (23 in m.openPorts) f += Finding("telnet", "منفذ Telnet مفتوح على الراوتر", "Telnet بلا تشفير ويُستغل كثيرًا.", Severity.CRITICAL, 95, "عطّل Telnet من إعدادات الراوتر.")
        if (21 in m.openPorts) f += Finding("ftp", "منفذ FTP مفتوح على الراوتر", "FTP بلا تشفير.", Severity.WARN, 80, "عطّله إن لم تكن بحاجة إليه.")
        if (80 in m.openPorts && 443 !in m.openPorts) f += Finding("http_admin", "واجهة الراوتر بلا تشفير", "تُدار عبر HTTP فقط.", Severity.INFO, 60, "فعّل HTTPS للإدارة إن كان مدعومًا.")
        if (m.defaultCred != null) f += Finding("default_cred", "كلمة مرور الراوتر افتراضية", "نجح الدخول بالبيانات ${m.defaultCred}.", Severity.CRITICAL, 99, "غيّر كلمة مرور الإدارة فورًا.")

        if (f.none { it.severity >= Severity.WARN }) {
            f += Finding("ok", "لا توجد مشكلة ظاهرة", "الاتصال المحلي والإنترنت وDNS ضمن الحدود الطبيعية في هذا الفحص.", Severity.OK, 70, null)
        }
        return f.sortedWith(compareByDescending<Finding> { it.severity.ordinal }.thenByDescending { it.confidence })
    }
}
