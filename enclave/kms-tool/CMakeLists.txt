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

    # Link-time fault injection exercises the installed SDK's actual request code.
    add_executable(swap-kms-sdk-cleanup-tests tests/sdk_cleanup.c)
    target_compile_features(swap-kms-sdk-cleanup-tests PRIVATE c_std_11)
    target_compile_options(swap-kms-sdk-cleanup-tests PRIVATE -Wall -Wextra -Werror -Wpedantic)
    target_include_directories(swap-kms-sdk-cleanup-tests PRIVATE "${NITRO_SDK_INCLUDE_DIR}")
    target_link_libraries(swap-kms-sdk-cleanup-tests PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
    foreach(symbol aws_mutex_init aws_condition_variable_init aws_condition_variable_wait
            aws_input_stream_new_from_cursor aws_http_message_new_request aws_mem_calloc
            aws_http_message_new_response aws_signable_new_http_request aws_signable_destroy
            aws_http_stream_release aws_sign_request_aws aws_apply_signing_result_to_http_request
            aws_http_connection_make_request aws_http_stream_activate)
        target_link_options(swap-kms-sdk-cleanup-tests PRIVATE "-Wl,--wrap=${symbol}")
    endforeach()
    add_test(NAME sdk-request-cleanup COMMAND swap-kms-sdk-cleanup-tests)
    set_tests_properties(sdk-request-cleanup PROPERTIES TIMEOUT 60)
endif()
