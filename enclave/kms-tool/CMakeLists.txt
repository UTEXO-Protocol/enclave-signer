cmake_minimum_required(VERSION 3.16)
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

add_executable(swap-kms-tool main.c)
target_link_options(swap-kms-tool PRIVATE "-Wl,--wrap=aws_client_bootstrap_new")
target_compile_features(swap-kms-tool PRIVATE c_std_11)
target_compile_options(swap-kms-tool PRIVATE -Wall -Wextra -Werror -Wpedantic)
target_include_directories(swap-kms-tool PRIVATE "${NITRO_SDK_INCLUDE_DIR}")
target_link_libraries(swap-kms-tool PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
install(TARGETS swap-kms-tool RUNTIME DESTINATION bin)
