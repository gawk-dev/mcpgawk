package dev.gawk.mcpgawk

import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service

/**
 * Where the engine lives. Configurable because users install with pipx, pip, homebrew or into a
 * virtualenv, and guessing wrong produces a panel that looks broken rather than one that explains.
 */
@Service(Service.Level.APP)
@State(name = "McpgawkSettings", storages = [Storage("mcpgawk.xml")])
class McpgawkSettings : PersistentStateComponent<McpgawkSettings.State> {
    data class State(var cliPath: String = "mcpgawk")

    private var state = State()

    var cliPath: String
        get() = state.cliPath
        set(value) { state.cliPath = value }

    override fun getState(): State = state
    override fun loadState(s: State) { state = s }

    companion object {
        val instance: McpgawkSettings get() = service()
    }
}
