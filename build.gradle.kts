plugins {
    id("me.champeau.jmh") version "0.6.8"
    id("com.google.osdetector") version "1.6.2"
}

group = "org.example.tink.bm"
version = "1.0.0-SNAPSHOT"

val osdetector: com.google.gradle.osdetector.OsDetector by extensions

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    val conscryptVersion = when (osdetector.classifier) {
        "osx-aarch_64" -> "2.6-SNAPSHOT"
        else -> "2.6.4"
    }

    jmh("pl.project13.scala:sbt-jmh-extras:0.3.7")
    implementation("org.openjdk.jmh:jmh-core:1.35")

    implementation("com.google.protobuf:protobuf-java:3.19.3")

    implementation("com.google.crypto.tink:tink:1.7.0")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    implementation("org.conscrypt:conscrypt-openjdk:${conscryptVersion}") {
        artifact {
            classifier = osdetector.classifier
        }
    }
}

jmh {
    rootProject.findProperty("jmh.includes")?.also {
        includes.set(it.toString().split(','))
    }
    rootProject.findProperty("jmh.profilers")?.also {
        profilers.set(it.toString().split(','))
    }
}
