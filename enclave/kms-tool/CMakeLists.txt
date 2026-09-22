cmake_minimum_required(VERSION 3.18)
project(kms-tool C)

# The SDK's installed export names LibJsonC::Json but does not discover it.
# Alias the installed json-c package instead of borrowing SDK Find modules.
find_package(json-c CONFIG REQUIRED)
if(NOT TARGET LibJsonC::Json)
    add_library(LibJsonC::Json ALIAS json-c::json-c)
endif()
find_package(aws-nitro-enclaves-sdk-c CONFIG REQUIRED)
# The build installs this pinned upstream header verbatim.
find_path(NITRO_SDK_INCLUDE_DIR aws/nitro_enclaves/internal/cms.h REQUIRED)

add_executable(kms-tool main.c)
target_link_options(kms-tool PRIVATE "-Wl,--wrap=aws_client_bootstrap_new")
target_compile_features(kms-tool PRIVATE c_std_11)
target_compile_options(kms-tool PRIVATE -Wall -Wextra -Werror -Wpedantic)
target_include_directories(kms-tool PRIVATE "${NITRO_SDK_INCLUDE_DIR}")
target_link_libraries(kms-tool PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
install(TARGETS kms-tool RUNTIME DESTINATION bin)
