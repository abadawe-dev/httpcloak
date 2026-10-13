cmake_minimum_required(VERSION 3.22.1)
project(httpcloak_jni C)

# libhttpcloak.so is the Go library from bindings/clib, cross-compiled for this
# ABI by the buildGo* Gradle tasks. HTTPCLOAK_GO_OUT is passed in by Gradle.
set(GO_OUT "${HTTPCLOAK_GO_OUT}/${ANDROID_ABI}")

add_library(httpcloak SHARED IMPORTED)
set_target_properties(httpcloak PROPERTIES IMPORTED_LOCATION "${GO_OUT}/libhttpcloak.so")

add_library(httpcloak_jni SHARED httpcloak_jni.c)
target_include_directories(httpcloak_jni PRIVATE "${GO_OUT}")
target_compile_options(httpcloak_jni PRIVATE -Wall -Wextra -Wno-unused-parameter)
# Android 15+ devices may use 16 KB pages; Play requires native code to support them.
target_link_options(httpcloak_jni PRIVATE "-Wl,-z,max-page-size=16384")
target_link_libraries(httpcloak_jni PRIVATE httpcloak)
