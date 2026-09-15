/* Exercise the actual response gate, official SDK response parsers and output
 * encoder. No service, credentials, NSM replacement or crypto hooks are used. */
#define main swap_kms_tool_main
#include "../main.c"
#undef main

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "response contract check failed at line %d\n", __LINE__); \
        return EXIT_FAILURE; \
    } \
} while (0)

static const char expected_key[] = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012";
static const char other_key[] = "arn:aws:kms:eu-west-1:123456789012:key/87654321-1234-1234-1234-123456789012";

int main(void) {
    aws_nitro_enclaves_library_init(NULL);
    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    struct input input = {.key_arn = expected_key};
    size_t key_cases = 0, error_cases = 0;
    const char *operations[] = {"generate", "decrypt"};
    for (size_t operation = 0; operation < 2; operation++) {
        input.operation = operations[operation];
        for (int variant = 0; variant < 10; variant++) {
            struct json_object *body = json_object_new_object();
            CHECK(body != NULL);
            CHECK(json_object_object_add(body, "CiphertextBlob", json_object_new_string("AA==")) == 0);
            CHECK(json_object_object_add(body, "CiphertextForRecipient", json_object_new_string("AA==")) == 0);
            CHECK(json_object_object_add(body, "EncryptionAlgorithm", json_object_new_string("SYMMETRIC_DEFAULT")) == 0);
            struct json_object *key = NULL;
            switch (variant) {
                case 0: key = json_object_new_string(expected_key); break;
                case 1: key = json_object_new_string(other_key); break;
                case 2: break; /* absent */
                case 3: break; /* explicit null */
                case 4: key = json_object_new_int(42); break;
                case 5: key = json_object_new_object(); break;
                case 6: key = json_object_new_array(); break;
                case 7: key = json_object_new_string(""); break;
                case 8: key = json_object_new_string_len(expected_key, (int)sizeof(expected_key)); break; /* embedded NUL */
                case 9: {
                    char long_key[130];
                    memset(long_key, 'x', sizeof(long_key));
                    key = json_object_new_string_len(long_key, (int)sizeof(long_key));
                    break;
                }
            }
            if (variant != 2) {
                CHECK(json_object_object_add(body, "KeyId", key) == 0);
            }
            struct aws_string *validated = validated_kms_json(allocator, &input, body);
            CHECK((validated != NULL) == (variant == 0));
            if (validated) {
                struct aws_kms_generate_data_key_response *generated = NULL;
                struct aws_kms_decrypt_response *decrypted = NULL;
                struct aws_string *response_key;
                if (operation == 0) {
                    generated = aws_kms_generate_data_key_response_from_json(allocator, validated);
                    CHECK(generated != NULL);
                    response_key = generated->key_id;
                } else {
                    decrypted = aws_kms_decrypt_response_from_json(allocator, validated);
                    CHECK(decrypted != NULL);
                    response_key = decrypted->key_id;
                }
                CHECK(response_key_matches(response_key, expected_key));
                CHECK(!response_key_matches(response_key, other_key));
                CHECK(!response_key_matches(NULL, expected_key));
                /* A post-request mutation of input cannot change output provenance. */
                input.key_arn = other_key;
                unsigned char payload[] = {7, 8, 9};
                struct aws_byte_buf value = aws_byte_buf_from_array(payload, sizeof(payload));
                int fds[2];
                CHECK(fflush(stdout) == 0 && pipe(fds) == 0);
                int saved_stdout = dup(STDOUT_FILENO);
                CHECK(saved_stdout >= 0 && dup2(fds[1], STDOUT_FILENO) == STDOUT_FILENO);
                close(fds[1]);
                const char *field = operation == 0 ? "ciphertext" : "seed";
                CHECK(print_result(allocator, response_key, field, &value));
                CHECK(fflush(stdout) == 0 && dup2(saved_stdout, STDOUT_FILENO) == STDOUT_FILENO);
                close(saved_stdout);
                char output[1024];
                ssize_t length = read(fds[0], output, sizeof(output));
                close(fds[0]);
                CHECK(length > 0 && (size_t)length < sizeof(output));
                struct json_object *emitted = parse_json(output, (size_t)length);
                CHECK(emitted != NULL && json_object_object_length(emitted) == 2);
                CHECK(strcmp(string_field(emitted, "key_arn", 1, 128), expected_key) == 0);
                CHECK(strcmp(string_field(emitted, field, 1, 16), "BwgJ") == 0);
                json_object_put(emitted);
                input.key_arn = expected_key;
                aws_kms_generate_data_key_response_destroy(generated);
                aws_kms_decrypt_response_destroy(decrypted);
            }
            aws_string_destroy_secure(validated);
            json_object_put(body);
            key_cases++;
        }
    }

    const struct { int status; const char *body; enum helper_status expected; } errors[] = {
        {403, "{}", HELPER_AUTHORIZATION},
        {401, "{}", HELPER_AUTHORIZATION},
        {429, "{}", HELPER_KMS_TEMPORARY},
        {500, "{}", HELPER_KMS_TEMPORARY},
        {503, "{}", HELPER_KMS_TEMPORARY},
        {400, "{\"__type\":\"AccessDeniedException\",\"message\":\"secret-test-value\"}", HELPER_AUTHORIZATION},
        {400, "{\"__type\":\"com.amazonaws.kms#AccessDeniedException\"}", HELPER_AUTHORIZATION},
        {400, "{\"__type\":\"ExpiredTokenException\"}", HELPER_AUTHORIZATION},
        {400, "{\"__type\":\"UnrecognizedClientException\"}", HELPER_AUTHORIZATION},
        {400, "{\"__type\":\"InvalidSignatureException\"}", HELPER_AUTHORIZATION},
        {400, "{\"__type\":\"ThrottlingException\"}", HELPER_KMS_TEMPORARY},
        {400, "{\"__type\":\"DependencyTimeoutException\"}", HELPER_KMS_TEMPORARY},
        {400, "{\"__type\":\"KMSInternalException\"}", HELPER_KMS_TEMPORARY},
        {400, "{\"__type\":\"KeyUnavailableException\"}", HELPER_KMS_TEMPORARY},
        {400, "{\"__type\":\"InvalidCiphertextException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"IncorrectKeyException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"DisabledException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"NotFoundException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"KMSInvalidStateException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"InvalidKeyUsageException\"}", HELPER_KEY_OR_CIPHERTEXT},
        {400, "{\"__type\":\"ValidationException\"}", HELPER_CONFIGURATION},
        {400, "{\"__type\":\"InvalidArnException\"}", HELPER_CONFIGURATION},
        {400, "{\"__type\":\"UnsupportedOperationException\"}", HELPER_CONFIGURATION},
        {400, "{\"message\":\"ThrottlingException\"}", HELPER_INVALID_RESPONSE},
        {400, "{\"__type\":\"unknown#ThrottlingException\"}", HELPER_INVALID_RESPONSE},
        {400, "{\"__type\":\"ThrottlingException\\u0000hidden\"}", HELPER_INVALID_RESPONSE},
        {400, "{\"__type\":42}", HELPER_INVALID_RESPONSE},
        {400, "not-json", HELPER_INVALID_RESPONSE},
        {404, "{\"__type\":\"ThrottlingException\"}", HELPER_INVALID_RESPONSE},
        {302, "{}", HELPER_INVALID_RESPONSE},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
        struct json_object *json = parse_json(errors[i].body, strlen(errors[i].body));
        CHECK(classify_kms_error(errors[i].status, json) == errors[i].expected);
        json_object_put(json);
        error_cases++;
    }
    CHECK(classify_sdk_failure(AWS_IO_SOCKET_TIMEOUT) == HELPER_TRANSPORT);
    CHECK(classify_sdk_failure(AWS_ERROR_HTTP_CONNECTION_CLOSED) == HELPER_TRANSPORT);
    CHECK(classify_sdk_failure(AWS_IO_TLS_HOST_NAME_MISMATCH) == HELPER_INVALID_RESPONSE);
    CHECK(classify_sdk_failure(AWS_IO_TLS_UNKNOWN_ROOT_CERTIFICATE) == HELPER_INVALID_RESPONSE);
    CHECK(classify_sdk_failure(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE) == HELPER_INVALID_RESPONSE);
    CHECK(classify_sdk_failure(AWS_ERROR_OOM) == HELPER_INTERNAL);
    CHECK(classify_sdk_failure(0) == HELPER_INTERNAL);
    CHECK(classify_sdk_failure(-1) == HELPER_INTERNAL);
    error_cases += 8;
    aws_nitro_enclaves_library_clean_up();
    printf("response key/output cases: %zu PASS; safe error classifications: %zu PASS\n", key_cases, error_cases);
    return EXIT_SUCCESS;
}
