package com.radar.netdiag.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.radar.netdiag.core.Diagnoser
import com.radar.netdiag.core.Options
import com.radar.netdiag.core.Report
import com.radar.netdiag.core.ReportStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class UiState(
    val running: Boolean = false, val stage: String = "", val progress: Float = 0f,
    val report: Report? = null, val history: List<Report> = emptyList()
)

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val store = ReportStore(app)
    private val _state = MutableStateFlow(UiState(history = store.list()))
    val state: StateFlow<UiState> = _state

    fun run(credCheck: Boolean, bloat: Boolean) {
        if (_state.value.running) return
        _state.update { it.copy(running = true, progress = 0f, stage = "") }
        viewModelScope.launch(Dispatchers.IO) {
            val r = try {
                Diagnoser(getApplication<Application>()).run(Options(credCheck, bloat)) { s, p ->
                    _state.update { it.copy(stage = s, progress = p) }
                }
            } catch (e: Exception) { null }
            if (r != null) store.save(r)
            _state.update { it.copy(running = false, progress = 1f, report = r ?: it.report, history = store.list()) }
        }
    }

    fun show(r: Report) { _state.update { it.copy(report = r) } }
}
