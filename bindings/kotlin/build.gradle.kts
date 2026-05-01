plugins {
    kotlin("jvm") version "1.9.24"
}

group = "org.pack.protocol"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

sourceSets {
    main {
        kotlin.srcDirs("src/main/kotlin")
    }
    test {
        kotlin.srcDirs("src/test/kotlin")
    }
}

// Path to the native library built by the pack-protocol-jni Rust crate.
// By default, cargo produces the shared library under the workspace
// target directory. Override with -PnativeLibDir=<path> if needed.
val nativeLibDir: String by project.extra {
    rootProject.projectDir.resolve("../../target/release").absolutePath
}

tasks.test {
    useJUnitPlatform()

    // Make the Rust-built shared library available at test time so that
    // System.loadLibrary("pack_protocol_jni") can find it.
    jvmArgs("-Djava.library.path=$nativeLibDir")
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
