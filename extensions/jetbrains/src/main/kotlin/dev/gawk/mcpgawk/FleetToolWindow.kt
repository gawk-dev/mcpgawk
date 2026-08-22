package dev.gawk.mcpgawk

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.icons.AllIcons
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.DefaultActionGroup
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBLabel
import com.intellij.ui.treeStructure.Tree
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import javax.swing.Icon
import javax.swing.JPanel
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeSelectionModel

/**
 * The tool window — the JetBrains face of the same fleet the CLI prints.
 *
 * One plugin covers every JetBrains IDE (IDEA, PyCharm, WebStorm, GoLand, RustRover, Rider, Android
 * Studio): they all run the IntelliJ Platform, so this is built once against the platform rather
 * than per-product.
 */
class FleetToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = FleetPanel(project)
        val content = toolWindow.contentManager.factory.createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
        toolWindow.setTitleActions(panel.titleActions())
        panel.refresh(launchLocal = false)
    }
}

class FleetPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val root = DefaultMutableTreeNode("fleet")
    private val model = DefaultTreeModel(root)
    private val tree = Tree(model).apply {
        isRootVisible = false
        showsRootHandles = true
        selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
        cellRenderer = FleetCellRenderer()
    }
    private val message = JBLabel().apply { border = JBUI.Borders.empty(8) }

    init {
        add(com.intellij.ui.ScrollPaneFactory.createScrollPane(tree), BorderLayout.CENTER)
        add(message, BorderLayout.SOUTH)
    }

    fun titleActions(): List<AnAction> = listOf(RefreshAction(), ScanLocalAction(), SignInAction())

    fun refresh(launchLocal: Boolean) {
        // Off the EDT: a fleet scan can legitimately take a minute when local servers are launched,
        // and freezing the whole IDE for it would be indefensible.
        object : Task.Backgroundable(project, "Scanning MCP servers…", true) {
            override fun run(indicator: ProgressIndicator) {
                val result = runCatching { Fleet.scan(settingsCommand(), launchLocal) }
                ApplicationManager.getApplication().invokeLater { render(result) }
            }
        }.queue()
    }

    private fun render(result: Result<FleetPayload>) {
        root.removeAllChildren()
        result.onSuccess { payload ->
            for (group in payload.groups) {
                val node = DefaultMutableTreeNode(GroupNode(group.title, payload.serversOf(group).size))
                for (server in payload.serversOf(group)) node.add(DefaultMutableTreeNode(server))
                root.add(node)
            }
            // The engine's own caveat travels with the data — the panel must not present the list as
            // definitive when the engine says it may not be.
            message.text = if (payload.unscannableMayBeIncomplete) {
                "${payload.scannable} scannable · ${payload.unscannable} run outside this machine " +
                    "(listed from local traces; may be incomplete)"
            } else {
                "${payload.scannable} servers scanned"
            }
        }.onFailure { err ->
            // Shown IN the panel. An empty tree plus a notification that vanishes reads as "you have
            // no MCP servers" — a false all-clear, which is the one thing this product must never do.
            val fe = err as? FleetException
            message.text = "<html>${fe?.message ?: err.message}<br/>${fe?.remedy ?: "Run `mcpgawk scan` in a terminal."}</html>"
        }
        model.reload()
        expandAll()
    }

    private fun expandAll() {
        for (i in 0 until tree.rowCount) tree.expandRow(i)
    }

    private fun selectedServer(): FleetServer? =
        ((tree.lastSelectedPathComponent as? DefaultMutableTreeNode)?.userObject as? FleetServer)

    private fun settingsCommand(): String = McpgawkSettings.instance.cliPath.ifBlank { "mcpgawk" }

    private inner class RefreshAction : AnAction("Re-scan MCP Servers", null, AllIcons.Actions.Refresh) {
        override fun actionPerformed(e: AnActionEvent) = refresh(launchLocal = false)
        override fun getActionUpdateThread() = ActionUpdateThread.EDT
    }

    private inner class ScanLocalAction :
        AnAction("Scan Local Servers Too (Launches Them)", null, AllIcons.Actions.Execute) {
        override fun actionPerformed(e: AnActionEvent) {
            // Explicit, consequence-stated confirmation. Scanning a local server RUNS ITS CODE.
            //
            // showYesNoDialog focuses YES by default, which made "Launch and Scan" answerable by a
            // single stray Enter or Space — plausible immediately after clicking the toolbar icon.
            // Observed for real in a manual pass: seven local servers launched and the user saw no
            // dialog at all, because it appeared and was dismissed within one keystroke. A dialog
            // that guards code execution must never have the executing option under the cursor.
            val choice = Messages.showDialog(
                project,
                "Scan local servers too? This LAUNCHES each one, which runs its code on your machine.",
                "mcpgawk",
                arrayOf(LAUNCH_OPTION, "Cancel"),
                CANCEL_INDEX,          // the DEFAULT: a reflex keypress cancels, it does not launch
                Messages.getWarningIcon(),
            )
            if (shouldLaunchLocal(choice)) refresh(launchLocal = true)
        }
        override fun getActionUpdateThread() = ActionUpdateThread.EDT
    }

    private inner class SignInAction : AnAction("Sign In to Server", null, AllIcons.General.User) {
        override fun actionPerformed(e: AnActionEvent) {
            val server = selectedServer()
            if (server?.url == null || !server.canAuthenticate) {
                Messages.showInfoMessage(project, "Select a server that needs credentials.", "mcpgawk")
                return
            }
            // A visible terminal, not a silent background call: this opens a browser and obtains a
            // credential, and the user should watch it happen.
            val cmd = GeneralCommandLine(settingsCommand()).withParameters(Fleet.signInArgs(server.url))
            // The Terminal plugin is an OPTIONAL dependency (see plugin.xml) so this plugin loads in
            // EVERY JetBrains IDE. Reached reflectively for that reason: a hard reference would make
            // this class fail to load wherever the terminal is absent, taking the whole panel with
            // it — a missing convenience must not cost the user the entire fleet view.
            val opened = runCatching {
                val mgrClass = Class.forName("org.jetbrains.plugins.terminal.TerminalToolWindowManager")
                val mgr = mgrClass.getMethod("getInstance", Project::class.java).invoke(null, project)
                val widget = mgrClass
                    .getMethod("createLocalShellWidget", String::class.java, String::class.java)
                    .invoke(mgr, project.basePath, "mcpgawk sign-in")
                widget.javaClass.getMethod("executeCommand", String::class.java)
                    .invoke(widget, cmd.commandLineString)
            }.isSuccess
            if (!opened) {
                // Still actionable without a terminal: hand the user the exact command.
                Messages.showInfoMessage(
                    project,
                    "Run this to sign in:\n\n${cmd.commandLineString}",
                    "mcpgawk",
                )
            }
        }
        override fun getActionUpdateThread() = ActionUpdateThread.EDT
    }
}

const val LAUNCH_OPTION = "Launch and Scan"
const val LAUNCH_INDEX = 0
const val CANCEL_INDEX = 1

/**
 * Whether a dialog result means "run their code".
 *
 * Pure and separate so the rule is testable: ONLY the explicit launch option launches. A dialog
 * closed with Escape, the window's close button, or any platform result that is not the launch
 * index (`-1` when dismissed) must be a refusal. Defaulting to launch on an ambiguous answer is how
 * a consent prompt becomes decoration.
 */
fun shouldLaunchLocal(choice: Int): Boolean = choice == LAUNCH_INDEX

data class GroupNode(val title: String, val count: Int)

/** Icons chosen so BLOCKED states read as warnings, not errors: the server is not broken, we simply
 *  have not been allowed to look at it. */
fun iconFor(state: String): Icon = when (state) {
    "AUTH" -> AllIcons.General.User
    // FAILED is the one blocked state that IS the server being broken — it ran and reported a
    // fault — so it gets the error icon the comment above withholds from the rest. TIMED-OUT stays
    // a warning: it may answer on a slower run.
    "FAILED" -> AllIcons.General.Error
    "TIMED-OUT" -> AllIcons.General.Warning
    "UNREACHABLE" -> AllIcons.General.Warning
    "SKIPPED" -> AllIcons.General.InspectionsEye
    "NOT-SCANNABLE" -> AllIcons.General.Web
    "REVIEW" -> AllIcons.General.BalloonWarning
    "INCOMPLETE" -> AllIcons.General.QuestionDialog
    "CLEAN" -> AllIcons.General.InspectionsOK
    else -> AllIcons.General.Information
}

class FleetCellRenderer : com.intellij.ui.ColoredTreeCellRenderer() {
    override fun customizeCellRenderer(
        tree: javax.swing.JTree,
        value: Any?,
        selected: Boolean,
        expanded: Boolean,
        leaf: Boolean,
        row: Int,
        hasFocus: Boolean,
    ) {
        when (val obj = (value as? DefaultMutableTreeNode)?.userObject) {
            is GroupNode -> {
                append(obj.title, com.intellij.ui.SimpleTextAttributes.REGULAR_BOLD_ATTRIBUTES)
                append("  (${obj.count})", com.intellij.ui.SimpleTextAttributes.GRAYED_ATTRIBUTES)
            }
            is FleetServer -> {
                icon = iconFor(obj.state)
                append("${obj.state}  ", com.intellij.ui.SimpleTextAttributes.GRAYED_ATTRIBUTES)
                append(obj.name)
                append("   ${obj.detail}", com.intellij.ui.SimpleTextAttributes.GRAYED_ATTRIBUTES)
                toolTipText = buildString {
                    append("${obj.state} — ${obj.detail}")
                    if (obj.clients.size > 1) {
                        // Worth saying: it is configured in several tools, so removing it from one
                        // leaves it running in the others.
                        append("\nConfigured in: ${obj.clients.joinToString(", ")}")
                    }
                    obj.url?.let { append("\n$it") }
                }
            }
            else -> append(obj?.toString() ?: "")
        }
    }
}
