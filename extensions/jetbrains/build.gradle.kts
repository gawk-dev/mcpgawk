plugins {
    kotlin("jvm") version "2.0.21"
    id("org.jetbrains.intellij.platform") version "2.1.0"
}

group = "dev.gawk"
version = providers.gradleProperty("pluginVersion").get()

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform {
        create(
            providers.gradleProperty("platformType").get(),
            providers.gradleProperty("platformVersion").get(),
        )
        // Required by the platform's `instrumentCode` step (it needs a Java compiler to weave
        // @NotNull assertions and form bindings). Without it the build fails after compiling.
        instrumentationTools()
        // JetBrains' own compatibility verifier. It is what the Marketplace runs on submission, so
        // running it here means a compatibility break is caught in the build, not in review.
        pluginVerifier()
    }
    // kotlinx-serialization is deliberately NOT used: the platform ships a JSON parser, and every
    // extra runtime dependency in a plugin is another thing that can clash with the host IDE's
    // classpath. The payload is small and the parsing is trivial.

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// This plugin shipped with NO tests. The two properties that matter most — refuse an unknown
// schema, and treat a non-zero exit WITH a payload as the answer — were correct in code and
// entirely unguarded, so a later refactor "fixing" the ignored exit code would have silently
// reintroduced the worst defect its sibling extension had, with nothing failing.
tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}

// IntelliJ Platform 2024.2 targets Java 21. Set the TARGET explicitly rather than using
// `jvmToolchain(21)`: the toolchain would demand a JDK 21 install, while any newer JDK can emit
// 21 bytecode perfectly well — one less thing a contributor has to have on their machine.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

intellijPlatform {
    pluginVerification {
        ides {
            // Verify against the OLDEST platform we claim to support. Passing only on the newest
            // would let `sinceBuild = "242"` become a promise the plugin cannot keep.
            ide(
                providers.gradleProperty("platformType").get(),
                providers.gradleProperty("platformVersion").get(),
            )
        }
    }

    // Publishing reads its secrets from the environment, never from this file and never from argv
    // (a token in argv is a token in `ps` and in shell history). Populate from the Keychain:
    //   export JETBRAINS_MARKETPLACE_TOKEN=$(security find-generic-password -s jetbrains-token -w)
    // The Marketplace requires every uploaded plugin to be SIGNED, so the certificate chain and
    // private key are read the same way. A missing value leaves the task unconfigured rather than
    // publishing something unsigned.
    publishing {
        token = providers.environmentVariable("JETBRAINS_MARKETPLACE_TOKEN")
    }

    signing {
        certificateChain = providers.environmentVariable("JETBRAINS_CERTIFICATE_CHAIN")
        privateKey = providers.environmentVariable("JETBRAINS_PRIVATE_KEY")
        password = providers.environmentVariable("JETBRAINS_PRIVATE_KEY_PASSWORD")
    }

    pluginConfiguration {
        ideaVersion {
            sinceBuild = "242"
            untilBuild = provider { null }   // don't pin an upper bound; it breaks on every IDE bump
        }
        // Without this the Marketplace listing shows an empty "What's New". Kept here rather than in
        // plugin.xml so it cannot drift from the version it describes.
        changeNotes = provider {
            """
            <h3>0.1.32</h3>
            <ul>
              <li>First release. One tool window listing every MCP server configured across your AI
                  tools, grouped by the tool it lives in, with what each one can reach and which
                  ones need attention.</li>
              <li>Local (stdio) servers are never launched by a refresh — scanning one runs its code,
                  so it takes an explicit action with the consequence stated.</li>
              <li>Sign-in is offered only on the servers that actually need credentials.</li>
              <li>Blocking a call and catching post-approval drift are the <code>mcpgawk</code> CLI
                  and its panel, not this tool window.</li>
              <li>Requires the engine: <code>pipx install mcpgawk</code>.</li>
            </ul>
            """.trimIndent()
        }
    }
}
