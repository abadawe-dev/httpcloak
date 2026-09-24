import org.gradle.internal.os.OperatingSystem

plugins {
    id("com.android.library")
    `maven-publish`
}

group = "io.github.sardanioss"
version = "1.7.2" // kept in step with the other bindings by bindings/bump-version.sh

val minSdkVersion = 24
val abis = providers.gradleProperty("httpcloak.abis").get()
    .split(',').map { it.trim() }.filter { it.isNotEmpty() }

android {
    namespace = "io.github.sardanioss.httpcloak"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = minSdkVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += abis }
        externalNativeBuild {
            cmake { arguments += "-DHTTPCLOAK_GO_OUT=${layout.buildDirectory.dir("go").get().asFile}" }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "httpcloak-android"
            afterEvaluate { from(components["release"]) }
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}

// ---------------------------------------------------------------------------
// The Go library (bindings/clib) cross-compiled with the NDK, one task per ABI.
// CMake links the JNI bridge against the result and AGP packages both.
// ---------------------------------------------------------------------------

// Android ABI -> GOARCH and the NDK clang target triple.
val goTargets = mapOf(
    "arm64-v8a" to ("arm64" to "aarch64-linux-android"),
    "armeabi-v7a" to ("arm" to "armv7a-linux-androideabi"),
    "x86_64" to ("amd64" to "x86_64-linux-android"),
    "x86" to ("386" to "i686-linux-android"),
)

val repoRoot = rootDir.resolve("../..")
val ndkHostTag = when {
    OperatingSystem.current().isMacOsX -> "darwin-x86_64"
    OperatingSystem.current().isWindows -> "windows-x86_64"
    else -> "linux-x86_64"
}
val clangSuffix = if (OperatingSystem.current().isWindows) "-clang.cmd" else "-clang"

val goBuildTasks = abis.map { abi ->
    val (goArch, triple) = goTargets[abi] ?: error("Unsupported ABI in httpcloak.abis: $abi")
    val outDir = layout.buildDirectory.dir("go/$abi")
    val compiler = androidComponents.sdkComponents.ndkDirectory.map {
        it.file("toolchains/llvm/prebuilt/$ndkHostTag/bin/$triple$minSdkVersion$clangSuffix").asFile.path
    }

    tasks.register<Exec>("buildGo-$abi") {
        description = "Cross-compiles libhttpcloak.so for $abi."
        inputs.files(fileTree(repoRoot) {
            include("**/*.go", "**/go.mod", "**/go.sum")
            exclude("**/*_test.go", "bindings/android/**", "examples/**", "tests/**")
        })
        outputs.dir(outDir)

        workingDir(repoRoot.resolve("bindings/clib"))
        environment("CGO_ENABLED", "1")
        environment("GOOS", "android")
        environment("GOARCH", goArch)
        if (goArch == "arm") environment("GOARM", "7")
        doFirst { environment("CC", compiler.get()) }
        // The soname lets the JNI bridge find this library by name at runtime,
        // and 16 KB alignment is required by Android 15+ devices and Play.
        commandLine(
            "go", "build", "-buildmode=c-shared", "-trimpath",
            "-ldflags=-s -w -extldflags=-Wl,-soname,libhttpcloak.so,-z,max-page-size=16384",
            "-o", outDir.get().file("libhttpcloak.so").asFile.path, ".",
        )
    }
}

tasks.configureEach {
    if (name.startsWith("configureCMake") || name.startsWith("buildCMake")) dependsOn(goBuildTasks)
}
