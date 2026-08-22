package dev.gawk.mcpgawk

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.util.ExecUtil
import com.intellij.util.EnvironmentUtil
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * The CLI boundary — run `mcpgawk scan --fleet-json` and parse what comes back.
 *
 * Exactly as in the VS Code extension, this plugin owns NO scanning and NO verdict logic. State,
 * one-line detail and grouping are computed once, in the Python engine, and rendered here. A third
 * definition of "is this server clean?" — after Python and TypeScript — would be three things to
 * keep in step, and nothing in any of the three test suites would notice them diverging.
 */

/** Bumped only on a breaking payload change. Pinned so an old plugin against a new engine fails
 *  loudly rather than half-rendering someone's security posture. */
const val SUPPORTED_SCHEMA = "mcpgawk.fleet/2"

/** The four places the engine is normally installed. Prepended to PATH so the CLI is found even
 *  when the IDE's environment does not include them. */
val INSTALL_ROOTS: List<String> = listOf(
    "${System.getProperty("user.home")}/.local/bin",   // uv tool / pipx
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "${System.getProperty("user.home")}/.cargo/bin",
)

/**
 * The environment the CLI runs under, derived rather than inherited.
 *
 * Two things go wrong when a child process simply takes what the IDE has:
 *
 *  * PATH. The platform's CONSOLE parent-environment loads a login shell's PATH, which usually
 *    contains the install roots — but only usually. When that probe fails (a documented IntelliJ
 *    failure mode) the CLI becomes unfindable, and the error blames the install. Prepending the
 *    roots makes finding the engine intentional instead of lucky. They are PREPENDED, never a
 *    replacement, so a deliberately-configured PATH still wins for everything else.
 *  * Python interpreter variables. The engine is a self-contained install with an absolute
 *    interpreter in its shebang; an inherited PYTHONHOME kills it outright and PYTHONEXECUTABLE
 *    makes it import a different mcpgawk, or none. Whatever the user's active virtualenv exported
 *    for their own project is not ours to run under. Anyone who genuinely needs a specific
 *    interpreter points the cliPath setting at that environment's binary.
 *
 * Pure, and takes the base map as an argument, so it is testable without an IDE.
 */
fun childEnvironment(base: Map<String, String>): Map<String, String> {
    val env = base.toMutableMap()
    for (key in listOf("PYTHONHOME", "PYTHONEXECUTABLE", "PYTHONPATH", "PYTHONSTARTUP")) {
        env.remove(key)
    }
    env["PATH"] = (INSTALL_ROOTS + listOfNotNull(base["PATH"]).filter { it.isNotEmpty() })
        .joinToString(":")
    return env
}

data class FleetServer(
    val name: String,
    val state: String,
    val detail: String,
    val url: String?,
    val clients: List<String>,
    val canAuthenticate: Boolean,
)

data class FleetGroup(val client: String, val title: String, val servers: List<String>)

data class FleetPayload(
    val servers: List<FleetServer>,
    val groups: List<FleetGroup>,
    val scannable: Int,
    val unscannable: Int,
    val unscannableMayBeIncomplete: Boolean,
) {
    fun serversOf(group: FleetGroup): List<FleetServer> {
        val byName = servers.associateBy { it.name }
        return group.servers.mapNotNull { byName[it] }
    }
}

/** A failure the user can act on. `remedy` is shown verbatim in the tool window — an error with no
 *  next step just makes someone close the panel. */
class FleetException(message: String, val remedy: String) : Exception(message)

object Fleet {

    /**
     * Run the engine and parse its payload.
     *
     * A NON-ZERO exit with a payload is the answer, not a failure: the CLI exits 1 when it finds
     * something. Treating that as a crash would hide exactly the fleets worth looking at.
     *
     * `launchLocal` is false for every automatic refresh. Scanning a local server LAUNCHES it, and
     * an IDE panel refreshing on open must never run untrusted code on the user's behalf.
     */
    fun scan(command: String, launchLocal: Boolean = false, timeoutMs: Int = 240_000): FleetPayload {
        val args = mutableListOf("scan", "--fleet-json")
        if (launchLocal) args.add("--yes")
        // NONE + an explicit map, rather than the default CONSOLE inheritance: the environment the
        // engine runs under is a decision, not a side effect of however the IDE was launched.
        // EnvironmentUtil.getEnvironmentMap() is still the base — that is the platform's login-shell
        // loader, and dropping it would lose the user's real PATH — but childEnvironment() then
        // guarantees the install roots are present and the Python overrides are not.
        val cmd = GeneralCommandLine(command)
            .withParameters(args)
            .withCharset(Charsets.UTF_8)
            .withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.NONE)
            .withEnvironment(childEnvironment(EnvironmentUtil.getEnvironmentMap()))

        val output = try {
            ExecUtil.execAndGetOutput(cmd, timeoutMs)
        } catch (e: Exception) {
            throw FleetException(
                "Could not run `$command`.",
                "Install the engine with `pipx install mcpgawk`, then set the path in " +
                    "Settings > Tools > mcpgawk if it lives somewhere unusual.",
            )
        }

        val stdout = output.stdout.trim()
        if (stdout.isEmpty() || !stdout.startsWith("{")) {
            if (output.isTimeout) {
                throw FleetException(
                    "The scan timed out.",
                    "A local server may be hanging on first launch. Run `mcpgawk scan` in a terminal to see which one.",
                )
            }
            throw FleetException(
                "mcpgawk returned no fleet data.",
                "Run `mcpgawk scan --fleet-json` in a terminal to see what it printed.",
            )
        }
        return parse(stdout)
    }

    fun parse(stdout: String): FleetPayload {
        // Gson, not org.json: Gson is bundled in the IntelliJ Platform, whereas org.json is NOT
        // guaranteed to be on a plugin's classpath and would fail at runtime in some IDEs.
        val root = try {
            JsonParser.parseString(stdout).asJsonObject
        } catch (e: Exception) {
            throw FleetException(
                "mcpgawk did not return valid JSON.",
                "Run `mcpgawk scan --fleet-json` in a terminal to see what it printed.",
            )
        }
        val schema = root.get("schema")?.asString.orEmpty()
        if (schema != SUPPORTED_SCHEMA) {
            // Refuse rather than guess. Showing four of eleven servers, or silently dropping a state
            // this build has never heard of, is a false all-clear — worse than an error message.
            throw FleetException(
                "This plugin understands $SUPPORTED_SCHEMA, but mcpgawk speaks ${schema.ifEmpty { "an unknown schema" }}.",
                "Update the plugin or the CLI so the two match.",
            )
        }
        val serversJson = root.getAsJsonArray("servers")
        val groupsJson = root.getAsJsonArray("groups")
        if (serversJson == null || groupsJson == null) {
            throw FleetException("mcpgawk returned an incomplete fleet.", "Re-run the scan.")
        }
        val summary = root.getAsJsonObject("summary") ?: JsonObject()
        return FleetPayload(
            servers = readServers(serversJson),
            groups = readGroups(groupsJson),
            scannable = summary.get("scannable")?.asInt ?: 0,
            unscannable = summary.get("unscannable")?.asInt ?: 0,
            unscannableMayBeIncomplete = summary.get("unscannable_may_be_incomplete")?.asBoolean ?: false,
        )
    }

    private fun strings(o: JsonObject, key: String): List<String> =
        o.getAsJsonArray(key)?.map { it.asString } ?: emptyList()

    private fun readServers(arr: JsonArray): List<FleetServer> = arr.map { el ->
        val o = el.asJsonObject
        val url = o.get("url")
        FleetServer(
            name = o.get("name").asString,
            state = o.get("state").asString,
            detail = o.get("detail")?.asString.orEmpty(),
            url = if (url == null || url.isJsonNull) null else url.asString,
            clients = strings(o, "clients"),
            canAuthenticate = o.get("can_authenticate")?.asBoolean ?: false,
        )
    }

    private fun readGroups(arr: JsonArray): List<FleetGroup> = arr.map { el ->
        val o = el.asJsonObject
        val client = o.get("client").asString
        FleetGroup(
            client = client,
            title = o.get("title")?.asString ?: client.uppercase(),
            servers = strings(o, "servers"),
        )
    }

    /** The argv for signing in to one server. Returned rather than executed so the caller can run it
     *  in a VISIBLE terminal: it opens a browser and obtains a credential, and the user should see
     *  that happen rather than find out afterwards. */
    fun signInArgs(url: String): List<String> = listOf("scan", "--http", url, "--login")
}
