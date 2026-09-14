cmake_minimum_required(VERSION 3.18)
project(swap-kms-tool C)

# The SDK's installed export names LibJsonC::Json but does not discover it.
# Alias the installed json-c package instead of borrowing SDK Find modules.
find_package(json-c CONFIG REQUIRED)
if(NOT TARGET LibJsonC::Json)
    add_library(LibJsonC::Json ALIAS json-c::json-c)
endif()
find_package(aws-nitro-enclaves-sdk-c CONFIG REQUIRED)
# The build installs this pinned upstream header verbatim with its checksum.
find_path(NITRO_SDK_INCLUDE_DIR aws/nitro_enclaves/internal/cms.h REQUIRED)

function(configure_helper_target target)
    target_link_options(${target} PRIVATE "-Wl,--wrap=aws_client_bootstrap_new")
    target_compile_features(${target} PRIVATE c_std_11)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -Wpedantic)
    target_include_directories(${target} PRIVATE "${NITRO_SDK_INCLUDE_DIR}")
    target_link_libraries(${target} PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
endfunction()

add_executable(swap-kms-tool main.c)
configure_helper_target(swap-kms-tool)
install(TARGETS swap-kms-tool RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    add_executable(swap-kms-tool-input-tests tests/input_cleanup.c)
    configure_helper_target(swap-kms-tool-input-tests)
    add_test(NAME credential-cleanup COMMAND swap-kms-tool-input-tests)
endif()
