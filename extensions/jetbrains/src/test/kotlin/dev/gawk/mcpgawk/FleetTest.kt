package dev.gawk.mcpgawk

import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/**
 * The plugin's first tests.
 *
 * It shipped with none, which mattered more than it looks: this file's subject is the boundary
 * where a security tool can lie. A panel that renders a PARTIAL fleet while looking authoritative,
 * or an empty one that reads as "you have no MCP servers", is a false all-clear — the failure this
 * whole product exists to prevent. Those guarantees were previously enforced by nothing.
 *
 * Everything here is pure parsing and environment construction, so no IDE fixture is needed.
 */
class FleetTest {

    private fun payload(
        schema: String = SUPPORTED_SCHEMA,
        servers: String = SERVERS,
        groups: String = GROUPS,
    ) = """
        {
          "schema": "$schema",
          "servers": [$servers],
          "groups": [$groups],
          "summary": {
            "counts": {"AUTH": 1, "REVIEW": 1},
            "scannable": 2,
            "unscannable": 1,
            "unscannable_may_be_incomplete": true
          }
        }
    """.trimIndent()

    companion object {
        private val SERVERS = """
            {"name":"figma","state":"AUTH","detail":"needs credentials — not scanned",
             "url":"https://f/mcp","clients":["codex"],"can_authenticate":true},
            {"name":"brandfetch","state":"REVIEW","detail":"6 tools · 4,243 tok · 4 can leak",
             "url":"https://b/mcp","clients":["claude-code"],"can_authenticate":false}
        """.trimIndent()
        private val GROUPS = """
            {"client":"codex","title":"CODEX","servers":["figma"]},
            {"client":"claude-code","title":"CLAUDE CODE","servers":["brandfetch"]}
        """.trimIndent()
    }

    @Test
    fun `parses the supported schema`() {
        val p = Fleet.parse(payload())
        assertEquals(2, p.servers.size)
        assertEquals("AUTH", p.servers[0].state)
        assertTrue(p.servers[0].canAuthenticate)
        assertEquals(2, p.scannable)
        assertTrue(p.unscannableMayBeIncomplete)
    }

    @Test
    fun `REFUSES a schema it does not understand rather than half-rendering a fleet`() {
        // Showing four of eleven servers is worse than an error: the user reads the four as all.
        // A version far enough ahead that no real bump reaches it. Naming the NEXT number made the
        // TypeScript twin of this test evaporate the moment that number shipped: it stopped
        // asserting "an unknown schema is refused" and started asserting the CURRENT one is.
        val e = assertFailsWith<FleetException> { Fleet.parse(payload(schema = "mcpgawk.fleet/999")) }
        assertContains(e.message!!, "mcpgawk.fleet/999")
        assertContains(e.remedy, "Update")
    }

    @Test
    fun `refuses a payload with no schema at all`() {
        val e = assertFailsWith<FleetException> { Fleet.parse("""{"servers":[],"groups":[]}""") }
        assertContains(e.message!!, "unknown schema")
    }

    @Test
    fun `rejects non-JSON instead of showing an empty fleet`() {
        assertFailsWith<FleetException> { Fleet.parse("not json") }
        assertFailsWith<FleetException> { Fleet.parse("") }
    }

    @Test
    fun `rejects a truncated payload rather than rendering half of it`() {
        val e = assertFailsWith<FleetException> {
            Fleet.parse("""{"schema":"$SUPPORTED_SCHEMA"}""")
        }
        assertContains(e.message!!, "incomplete")
    }

    @Test
    fun `carries the engine's state and detail through verbatim`() {
        // The plugin must never restate a verdict in its own words — that is a second definition.
        val p = Fleet.parse(payload())
        assertEquals("6 tools · 4,243 tok · 4 can leak", p.servers[1].detail)
    }

    @Test
    fun `drops a server named in a group but missing from the list, without crashing`() {
        val p = Fleet.parse(payload(groups = """{"client":"x","title":"X","servers":["ghost"]}"""))
        assertEquals(emptyList(), p.serversOf(p.groups[0]))
    }

    @Test
    fun `keeps a server that lives in two tools listed under both`() {
        // Removing it from one tool leaves it running in the other; showing it once would imply
        // otherwise.
        val p = Fleet.parse(
            payload(
                servers = """{"name":"pencil","state":"SKIPPED","detail":"local","url":null,
                    "clients":["kiro","gemini-cli"],"can_authenticate":false}""",
                groups = """{"client":"kiro","title":"KIRO","servers":["pencil"]},
                    {"client":"gemini-cli","title":"GEMINI CLI","servers":["pencil"]}""",
            ),
        )
        assertEquals(2, p.groups.size)
        assertEquals("pencil", p.serversOf(p.groups[0])[0].name)
        assertEquals("pencil", p.serversOf(p.groups[1])[0].name)
        assertNull(p.serversOf(p.groups[0])[0].url)
    }
}

/**
 * The environment the engine runs under. Pure by design — the whole point is that it can be checked
 * without an IDE, since the IDE's own environment is exactly the thing not to be trusted.
 */
class ChildEnvironmentTest {

    @Test
    fun `finds a CLI the IDE's own PATH cannot see`() {
        val env = childEnvironment(mapOf("PATH" to "/usr/bin:/bin"))
        assertContains(env["PATH"]!!, ".local/bin")      // uv tool / pipx land here
        assertContains(env["PATH"]!!, "/opt/homebrew/bin")
    }

    @Test
    fun `prepends rather than replaces, so a configured PATH still resolves`() {
        val env = childEnvironment(mapOf("PATH" to "/my/venv/bin"))
        assertTrue(env["PATH"]!!.endsWith("/my/venv/bin"))
    }

    @Test
    fun `survives an environment with no PATH at all`() {
        val env = childEnvironment(emptyMap())
        assertTrue(env["PATH"]!!.isNotEmpty())
        assertFalse(env["PATH"]!!.endsWith(":"))  // no empty trailing segment
    }

    @Test
    fun `drops interpreter overrides that would break a self-contained install`() {
        // PYTHONHOME kills the CLI outright; PYTHONEXECUTABLE makes it import a different mcpgawk.
        val env = childEnvironment(
            mapOf(
                "PATH" to "/usr/bin",
                "PYTHONHOME" to "/somewhere/else",
                "PYTHONEXECUTABLE" to "/somewhere/else/bin/python",
                "PYTHONPATH" to "/workspace/src",
                "PYTHONSTARTUP" to "/x.py",
            ),
        )
        assertFalse(env.containsKey("PYTHONHOME"))
        assertFalse(env.containsKey("PYTHONEXECUTABLE"))
        assertFalse(env.containsKey("PYTHONPATH"))
        assertFalse(env.containsKey("PYTHONSTARTUP"))
    }

    @Test
    fun `leaves the rest of the environment alone`() {
        // Proxy settings and credentials the servers legitimately need must survive.
        val env = childEnvironment(mapOf("PATH" to "/usr/bin", "HTTPS_PROXY" to "http://p:8080"))
        assertEquals("http://p:8080", env["HTTPS_PROXY"])
    }
}

/**
 * Consent to run other people's code.
 *
 * A manual pass launched seven local servers with no dialog the user could perceive: the platform's
 * yes/no helper focuses YES, so one stray keystroke answered it. The rule below is what remains
 * after moving the destructive option off the default — and it is deliberately conservative,
 * because the failure mode is executing untrusted code on someone's machine.
 */
class LocalScanConsentTest {

    @Test
    fun `only the explicit launch option launches`() {
        assertTrue(shouldLaunchLocal(LAUNCH_INDEX))
    }

    @Test
    fun `cancel does not launch`() {
        assertFalse(shouldLaunchLocal(CANCEL_INDEX))
    }

    @Test
    fun `a dismissed dialog does not launch`() {
        // Escape or the window close button yields -1. Treating an unanswered prompt as consent
        // would make the prompt decorative.
        assertFalse(shouldLaunchLocal(-1))
    }

    @Test
    fun `no other answer is ever taken as consent`() {
        for (choice in listOf(2, 3, 99, Int.MIN_VALUE, Int.MAX_VALUE)) {
            assertFalse(shouldLaunchLocal(choice), "choice $choice must not launch")
        }
    }

    @Test
    fun `cancel is the default, so a reflex keypress cannot launch anything`() {
        // The whole defect in one assertion: the button under the cursor must not be the one that
        // runs code.
        assertFalse(shouldLaunchLocal(CANCEL_INDEX))
        assertTrue(CANCEL_INDEX != LAUNCH_INDEX)
    }
}
