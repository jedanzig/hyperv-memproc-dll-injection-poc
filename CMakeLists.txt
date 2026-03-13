cmake_minimum_required(VERSION 3.20)

project(InjectorBridge LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "InjectorBridge must be built on Windows with a Visual Studio generator.")
endif()

# Dependency paths — override with -DMEMPROC_INCLUDE_DIR / -DMEMPROC_LIB_DIR
set(MEMPROC_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/main/dependencies" CACHE PATH "Path to MemProcFS/LeechCore headers")
set(MEMPROC_LIB_DIR "${CMAKE_SOURCE_DIR}/libs" CACHE PATH "Path to MemProcFS/LeechCore libraries")

# Validate that required headers exist
if(NOT EXISTS "${MEMPROC_INCLUDE_DIR}/vmmdll.h")
    message(FATAL_ERROR
        "vmmdll.h not found in ${MEMPROC_INCLUDE_DIR}.\n"
        "Download MemProcFS from https://github.com/ufrisk/MemProcFS and copy the required headers.\n"
        "See README.md for setup instructions.")
endif()

add_executable(injector_bridge
    main/bridge.cpp
)

# Test payload DLL — built separately and passed to injector_bridge at runtime
add_library(test_payload SHARED
    main/test_dll.cpp
)
target_compile_features(test_payload PRIVATE cxx_std_17)

target_compile_features(injector_bridge PRIVATE cxx_std_17)

target_include_directories(injector_bridge PRIVATE
    "${MEMPROC_INCLUDE_DIR}"
    "${CMAKE_SOURCE_DIR}/main"
)

target_link_libraries(injector_bridge PRIVATE
    "${MEMPROC_LIB_DIR}/vmm.lib"
    "${MEMPROC_LIB_DIR}/leechcore.lib"
)
