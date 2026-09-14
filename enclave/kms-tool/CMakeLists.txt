cmake_minimum_required(VERSION 3.16)
project(swap-kms-tool C)

set(NITRO_SDK_SOURCE_DIR "" CACHE PATH "Pinned, unmodified AWS Nitro Enclaves SDK source")
if(NOT EXISTS "${NITRO_SDK_SOURCE_DIR}/include/aws/nitro_enclaves/internal/cms.h")
    message(FATAL_ERROR "NITRO_SDK_SOURCE_DIR must point to the pinned SDK checkout")
endif()
# The SDK exports the CMS functions used by kmstool, but does not install their
# header or discover json-c in its installed package configuration.
list(APPEND CMAKE_MODULE_PATH "${NITRO_SDK_SOURCE_DIR}/cmake/modules")
find_package(LibJsonC REQUIRED)
find_package(aws-nitro-enclaves-sdk-c CONFIG REQUIRED)

add_executable(swap-kms-tool main.c)
target_compile_features(swap-kms-tool PRIVATE c_std_11)
target_compile_options(swap-kms-tool PRIVATE -Wall -Wextra -Werror -Wpedantic)
target_include_directories(swap-kms-tool PRIVATE "${NITRO_SDK_SOURCE_DIR}/include")
target_link_libraries(swap-kms-tool PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
install(TARGETS swap-kms-tool RUNTIME DESTINATION bin)
