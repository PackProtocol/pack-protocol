cmake_minimum_required(VERSION 3.16)
project(pack-protocol-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Header-only INTERFACE library
# ---------------------------------------------------------------------------
add_library(pack_protocol_cpp INTERFACE)

target_include_directories(pack_protocol_cpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# The C header lives in the FFI crate; consumers must be able to find it.
set(PACK_FFI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../crates/pack-protocol-ffi/include"
    CACHE PATH "Path to pack_protocol.h C header")

if(EXISTS "${PACK_FFI_INCLUDE_DIR}/pack_protocol.h")
    target_include_directories(pack_protocol_cpp INTERFACE
        $<BUILD_INTERFACE:${PACK_FFI_INCLUDE_DIR}>
    )
else()
    message(WARNING
        "pack_protocol.h not found at ${PACK_FFI_INCLUDE_DIR}. "
        "Set PACK_FFI_INCLUDE_DIR to the directory containing the C header.")
endif()

# ---------------------------------------------------------------------------
# Optional: find and link the pre-built pack_protocol_ffi shared/static library
# ---------------------------------------------------------------------------
option(PACK_LINK_FFI "Attempt to find and link libpack_protocol_ffi" ON)

if(PACK_LINK_FFI)
    # Look in the Cargo target directory by default.
    set(PACK_FFI_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release"
        CACHE PATH "Directory containing the built libpack_protocol_ffi library")

    find_library(PACK_FFI_LIBRARY
        NAMES pack_protocol_ffi
        HINTS "${PACK_FFI_LIB_DIR}"
    )

    if(PACK_FFI_LIBRARY)
        message(STATUS "Found pack_protocol_ffi: ${PACK_FFI_LIBRARY}")
        target_link_libraries(pack_protocol_cpp INTERFACE "${PACK_FFI_LIBRARY}")
    else()
        message(STATUS
            "libpack_protocol_ffi not found in ${PACK_FFI_LIB_DIR}. "
            "Build the Rust crate first (cargo build --release -p pack-protocol-ffi) "
            "or set PACK_FFI_LIB_DIR.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
option(PACK_BUILD_TESTS "Build C++ binding tests" OFF)

if(PACK_BUILD_TESTS)
    enable_testing()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests")
        # C++ tests
        file(GLOB TEST_CPP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
        if(TEST_CPP_SOURCES)
            foreach(test_src ${TEST_CPP_SOURCES})
                get_filename_component(test_name ${test_src} NAME_WE)
                add_executable(${test_name} ${test_src})
                target_link_libraries(${test_name} PRIVATE pack_protocol_cpp)
                add_test(NAME ${test_name} COMMAND ${test_name})
            endforeach()
        endif()

        # C tests (compiled as C, linked against the FFI library directly)
        file(GLOB TEST_C_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c")
        if(TEST_C_SOURCES)
            enable_language(C)
            foreach(test_src ${TEST_C_SOURCES})
                get_filename_component(test_name ${test_src} NAME_WE)
                add_executable(${test_name} ${test_src})
                target_include_directories(${test_name} PRIVATE
                    "${PACK_FFI_INCLUDE_DIR}")
                if(PACK_FFI_LIBRARY)
                    target_link_libraries(${test_name} PRIVATE
                        "${PACK_FFI_LIBRARY}")
                endif()
                add_test(NAME ${test_name} COMMAND ${test_name})
            endforeach()
        endif()
    endif()
endif()
