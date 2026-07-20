rootProject.name = "rampart-plugins"

pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://papermc.io/repo/repository/maven-public/")
    }
}

include("velocity", "paper")
