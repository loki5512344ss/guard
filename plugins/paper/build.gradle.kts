plugins {
    id("java")
    id("com.gradleup.shadow") version "9.0.0-beta2"
}

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly("io.papermc.paper:paper-api:1.21.3-R0.1-SNAPSHOT")
    implementation("redis.clients:jedis:5.2.0")
}

tasks {
    shadowJar {
        archiveBaseName.set("rampart-paper")
        archiveClassifier.set("")
        archiveVersion.set(project.property("version").toString())
    }

    build {
        dependsOn(shadowJar)
    }
}
