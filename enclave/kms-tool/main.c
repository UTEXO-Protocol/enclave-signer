/* RGB-swap custody adapter for the official AWS Nitro Enclaves SDK for C. */
#include <aws/common/hash_table.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/internal/cms.h>
#include <aws/common/encoding.h>
#include <aws/common/error.h>
#include <aws/http/http.h>
#include <aws/io/stream.h>
#include <aws/io/channel_bootstrap.h>
#include <json-c/json.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#define MESSAGE_LIMIT (64 * 1024)
#define CIPHERTEXT_LIMIT 6144
#define SEED_BYTES 64

/* Stable private IPC exit codes. Never forward service bodies or SDK diagnostics.
 * Rust maps these constants; unknown failures are never implicitly retryable. */
enum helper_status {
    HELPER_OK = 0,
    HELPER_CONFIGURATION = 64,
    HELPER_INVALID_RESPONSE = 65,
    HELPER_TRANSPORT = 69,
    HELPER_INTERNAL = 70,
    HELPER_KMS_TEMPORARY = 75,
    HELPER_AUTHORIZATION = 77,
    HELPER_KEY_OR_CIPHERTEXT = 78,
};

/* This SDK releases its bootstrap immediately after connecting. With its
 * pinned CRT, a peer closing HTTP can then tear down the event loop before
 * kms_client_destroy releases the connection. Keep a reference until that
 * release; all creation, transport and destruction still use official APIs.
 * This one-shot process creates exactly one KMS client. */
static struct aws_client_bootstrap *retained_bootstrap;

struct aws_client_bootstrap *__real_aws_client_bootstrap_new(
    struct aws_allocator *allocator, const struct aws_client_bootstrap_options *options);

struct aws_client_bootstrap *__wrap_aws_client_bootstrap_new(
    struct aws_allocator *allocator, const struct aws_client_bootstrap_options *options) {
    struct aws_client_bootstrap *bootstrap = __real_aws_client_bootstrap_new(allocator, options);
    if (bootstrap) {
        retained_bootstrap = aws_client_bootstrap_acquire(bootstrap);
    }
    return bootstrap;
}

struct input {
    struct json_object *json;
    const char *operation;
    const char *region;
    const char *key_arn;
    const char *seed_id;
    const char *network;
    const char *access_key;
    const char *secret_key;
    const char *session_token;
    const char *ciphertext;
};

static void wipe(void *buffer, size_t length) {
    volatile unsigned char *cursor = buffer;
    while (length--) {
        *cursor++ = 0;
    }
}

/* Erase live parsed credential copies through json-c's public mutator before
 * freeing them. For the pinned json-c, a same-length replacement reuses the
 * existing allocation (covered by the native test); no private layout access.
 * json-c parser scratch allocations still have process-lifetime confidentiality. */
static void erase_input_credentials(struct json_object *json) {
    static const char zeros[MESSAGE_LIMIT] = {0};
    const char *fields[] = {"access_key_id", "secret_access_key", "session_token"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct json_object *value = NULL;
        if (json_object_object_get_ex(json, fields[i], &value) &&
            json_object_get_type(value) == json_type_string) {
            int length = json_object_get_string_len(value);
            if (length > 0 && length <= MESSAGE_LIMIT) {
                (void)json_object_set_string_len(value, zeros, length);
            }
        }
    }
}

/* Credentials are never passed through argv, environment or files. */
static const char *string_field(struct json_object *object, const char *name, size_t min, size_t max) {
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(object, name, &value) ||
        json_object_get_type(value) != json_type_string) {
        return NULL;
    }
    const char *text = json_object_get_string(value);
    size_t length = (size_t)json_object_get_string_len(value);
    if (length < min || length > max || strlen(text) != length) {
        return NULL;
    }
    for (size_t i = 0; i < length; i++) {
        if ((unsigned char)text[i] < 0x21 || (unsigned char)text[i] > 0x7e) {
            return NULL;
        }
    }
    return text;
}

static struct json_object *parse_json(const char *data, size_t length) {
    struct json_tokener *tokener = json_tokener_new_ex(8);
    if (!tokener) {
        return NULL;
    }
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *object = json_tokener_parse_ex(tokener, data, (int)length);
    size_t end = json_tokener_get_parse_end(tokener);
    bool valid = json_tokener_get_error(tokener) == json_tokener_success;
    while (end < length && isspace((unsigned char)data[end])) {
        end++;
    }
    valid = valid && end == length && json_object_get_type(object) == json_type_object;
    json_tokener_free(tokener);
    if (!valid) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

/* json-c replaces duplicate members. After its JSON validation, count structural
 * member separators without decoding names or values. Accepted IPC has exactly
 * eight/nine known string fields, so this raw count must equal the parsed count.
 * Escaped quotes/colons stay inside strings; duplicate escaped names are caught
 * as well. This is a flat-message shape check, not a second JSON parser. */
static size_t json_member_separators(const char *data, size_t length) {
    bool in_string = false, escaped = false;
    size_t count = 0;
    for (size_t i = 0; i < length; i++) {
        char c = data[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else if (c == '"') {
            in_string = true;
        } else if (c == ':') {
            count++;
        }
    }
    return count;
}

static bool read_input(struct input *input) {
    char raw[MESSAGE_LIMIT + 1];
    size_t length = fread(raw, 1, sizeof(raw), stdin);
    if (ferror(stdin) || length == 0 || length > MESSAGE_LIMIT) {
        wipe(raw, sizeof(raw));
        return false;
    }
    input->json = parse_json(raw, length);
    size_t raw_members = input->json ? json_member_separators(raw, length) : 0;
    wipe(raw, sizeof(raw));
    if (!input->json) {
        return false;
    }
    input->operation = string_field(input->json, "operation", 1, 8);
    input->region = string_field(input->json, "region", 3, 32);
    input->key_arn = string_field(input->json, "key_arn", 1, 128);
    input->seed_id = string_field(input->json, "seed_id", 1, 128);
    input->network = string_field(input->json, "bitcoin_network", 1, 8);
    input->access_key = string_field(input->json, "access_key_id", 1, 128);
    input->secret_key = string_field(input->json, "secret_access_key", 1, 256);
    input->session_token = string_field(input->json, "session_token", 0, 16 * 1024);
    if (!input->operation || !input->region || !input->key_arn || !input->seed_id || !input->network ||
        !input->access_key || !input->secret_key || !input->session_token) {
        return false;
    }
    bool generate = !strcmp(input->operation, "generate");
    if (!generate && strcmp(input->operation, "decrypt")) {
        return false;
    }
    size_t expected_members = generate ? 8 : 9;
    if ((size_t)json_object_object_length(input->json) != expected_members || raw_members != expected_members) {
        return false;
    }
    if (!generate) {
        input->ciphertext = string_field(input->json, "ciphertext", 1, 8192);
        if (!input->ciphertext) {
            return false;
        }
    }
    /* Rust validates the measured region/key/seed configuration and typed
     * Bitcoin network before starting this fixed helper. Keep IPC bounds,
     * string types and framing here; do not maintain a second policy parser. */
    return true;
}

static bool add_context(struct aws_allocator *allocator, struct aws_hash_table *context, const struct input *input) {
    if (aws_hash_table_init(context, allocator, 4, aws_hash_string, aws_hash_callback_string_eq,
                           aws_hash_callback_string_destroy, aws_hash_callback_string_destroy)) {
        return false;
    }
    const char *keys[] = {"application", "flow", "seed_id", "bitcoin_network"};
    const char *values[] = {"utexo-enclave-signer", "rgb-swap", input->seed_id, input->network};
    for (size_t i = 0; i < 4; i++) {
        struct aws_string *key = aws_string_new_from_c_str(allocator, keys[i]);
        struct aws_string *value = aws_string_new_from_c_str(allocator, values[i]);
        if (!key || !value || aws_hash_table_put(context, key, value, NULL)) {
            aws_string_destroy(key);
            aws_string_destroy(value);
            return false;
        }
    }
    return true;
}

static struct aws_recipient *new_recipient(struct aws_nitro_enclaves_kms_client *client) {
    struct aws_recipient *recipient = aws_recipient_new(client->allocator);
    if (!recipient) {
        return NULL;
    }
    recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;
    if (aws_attestation_request(client->allocator, client->keypair, &recipient->attestation_document)) {
        aws_recipient_destroy(recipient);
        return NULL;
    }
    return recipient;
}

static struct aws_string *make_request(struct aws_nitro_enclaves_kms_client *client, const struct input *input) {
    struct aws_string *json = NULL;
    if (!strcmp(input->operation, "generate")) {
        struct aws_kms_generate_data_key_request *request = aws_kms_generate_data_key_request_new(client->allocator);
        if (!request) {
            return NULL;
        }
        request->key_id = aws_string_new_from_c_str(client->allocator, input->key_arn);
        request->number_of_bytes = SEED_BYTES;
        request->key_spec = AWS_KS_UNINITIALIZED;
        request->recipient = new_recipient(client);
        if (request->key_id && request->recipient && add_context(client->allocator, &request->encryption_context, input)) {
            json = aws_kms_generate_data_key_request_to_json(request);
        }
        aws_kms_generate_data_key_request_destroy(request);
    } else {
        struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(client->allocator);
        if (!request) {
            return NULL;
        }
        struct aws_byte_cursor encoded = aws_byte_cursor_from_c_str(input->ciphertext);
        size_t decoded_length = 0;
        request->key_id = aws_string_new_from_c_str(client->allocator, input->key_arn);
        request->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;
        request->recipient = new_recipient(client);
        if (request->key_id && request->recipient && !aws_base64_compute_decoded_len(&encoded, &decoded_length) &&
            decoded_length > 0 && decoded_length <= CIPHERTEXT_LIMIT &&
            !aws_byte_buf_init(&request->ciphertext_blob, client->allocator, decoded_length) &&
            !aws_base64_decode(&encoded, &request->ciphertext_blob) &&
            add_context(client->allocator, &request->encryption_context, input)) {
            json = aws_kms_decrypt_request_to_json(request);
        }
        aws_kms_decrypt_request_destroy(request);
    }
    return json;
}

/* Only documented transport failures are retryable. TLS authentication and
 * unknown/local SDK failures must not become optimistic retry advice. */
static enum helper_status classify_sdk_failure(int error) {
    switch (error) {
        case AWS_IO_BROKEN_PIPE:
        case AWS_IO_SOCKET_CONNECTION_REFUSED:
        case AWS_IO_SOCKET_TIMEOUT:
        case AWS_IO_SOCKET_NO_ROUTE_TO_HOST:
        case AWS_IO_SOCKET_NETWORK_DOWN:
        case AWS_IO_SOCKET_CLOSED:
        case AWS_IO_SOCKET_CONNECT_ABORTED:
        case AWS_IO_DNS_QUERY_AGAIN:
        case AWS_IO_TLS_NEGOTIATION_TIMEOUT:
        case AWS_ERROR_HTTP_CONNECTION_CLOSED:
        case AWS_ERROR_HTTP_SERVER_CLOSED:
            return HELPER_TRANSPORT;
        case AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE:
        case AWS_IO_TLS_UNKNOWN_ROOT_CERTIFICATE:
        case AWS_IO_TLS_CERTIFICATE_EXPIRED:
        case AWS_IO_TLS_CERTIFICATE_NOT_YET_VALID:
        case AWS_IO_TLS_BAD_CERTIFICATE:
        case AWS_IO_TLS_PEER_CERTIFICATE_EXPIRED:
        case AWS_IO_TLS_BAD_PEER_CERTIFICATE:
        case AWS_IO_TLS_PEER_CERTIFICATE_REVOKED:
        case AWS_IO_TLS_PEER_CERTIFICATE_UNKNOWN:
        case AWS_IO_TLS_INVALID_CERTIFICATE_CHAIN:
        case AWS_IO_TLS_HOST_NAME_MISMATCH:
            return HELPER_INVALID_RESPONSE;
        default:
            return HELPER_INTERNAL;
    }
}

/* These statuses/types come only from the SDK's authenticated KMS HTTPS
 * response. Inspect an allowlisted code, never the service's free-form message.
 * Unknown or malformed errors remain invalid responses, not retryable failures. */
static enum helper_status classify_kms_error(int status, struct json_object *json) {
    if (status == 401 || status == 403) {
        return HELPER_AUTHORIZATION;
    }
    if (status == 429 || (status >= 500 && status <= 599)) {
        return HELPER_KMS_TEMPORARY;
    }
    if (status != 400) {
        return HELPER_INVALID_RESPONSE;
    }
    const char *type = string_field(json, "__type", 1, 128);
    if (!type) {
        return HELPER_INVALID_RESPONSE;
    }
    static const char prefix[] = "com.amazonaws.kms#";
    if (!strncmp(type, prefix, sizeof(prefix) - 1)) {
        type += sizeof(prefix) - 1;
    }
    const struct { const char *name; enum helper_status status; } known[] = {
        {"AccessDeniedException", HELPER_AUTHORIZATION},
        {"UnrecognizedClientException", HELPER_AUTHORIZATION},
        {"ExpiredTokenException", HELPER_AUTHORIZATION},
        {"InvalidSignatureException", HELPER_AUTHORIZATION},
        {"ThrottlingException", HELPER_KMS_TEMPORARY},
        {"DependencyTimeoutException", HELPER_KMS_TEMPORARY},
        {"KMSInternalException", HELPER_KMS_TEMPORARY},
        {"KeyUnavailableException", HELPER_KMS_TEMPORARY},
        {"NotFoundException", HELPER_KEY_OR_CIPHERTEXT},
        {"DisabledException", HELPER_KEY_OR_CIPHERTEXT},
        {"IncorrectKeyException", HELPER_KEY_OR_CIPHERTEXT},
        {"InvalidCiphertextException", HELPER_KEY_OR_CIPHERTEXT},
        {"InvalidKeyUsageException", HELPER_KEY_OR_CIPHERTEXT},
        {"KMSInvalidStateException", HELPER_KEY_OR_CIPHERTEXT},
        {"ValidationException", HELPER_CONFIGURATION},
        {"InvalidArnException", HELPER_CONFIGURATION},
        {"UnsupportedOperationException", HELPER_CONFIGURATION},
    };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (!strcmp(type, known[i].name)) {
            return known[i].status;
        }
    }
    return HELPER_INVALID_RESPONSE;
}

/* Bind the actual KMS response KeyId to the measured request before the SDK
 * parser or CMS unwrap can consume the response. Both operations use this gate. */
static struct aws_string *validated_kms_json(struct aws_allocator *allocator,
                                            const struct input *input, struct json_object *json) {
    const char *key = string_field(json, "KeyId", 1, 128);
    if (!key || strcmp(key, input->key_arn)) {
        return NULL;
    }
    struct json_object *plaintext = NULL;
    if (json_object_object_get_ex(json, "Plaintext", &plaintext)) {
        if (json_object_get_type(plaintext) != json_type_null &&
            (json_object_get_type(plaintext) != json_type_string || json_object_get_string_len(plaintext) != 0)) {
            return NULL;
        }
        /* KMS may return null or an empty value with Recipient. The official
         * parser accepts absence; reject plaintext before this normalization. */
        json_object_object_del(json, "Plaintext");
    }
    const char *serialized = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN);
    return serialized ? aws_string_new_from_c_str(allocator, serialized) : NULL;
}

/* The SDK's convenience methods discard response KeyId/algorithm. Use its
 * public REST and JSON APIs so these application checks precede CMS unwrap. */
static enum helper_status call_kms(struct aws_nitro_enclaves_kms_client *client,
                                   const struct input *input, struct aws_string **result) {
    struct aws_string *request = make_request(client, input);
    if (!request) {
        return HELPER_INTERNAL;
    }
    const char *target = !strcmp(input->operation, "generate") ? "TrentService.GenerateDataKey" : "TrentService.Decrypt";
    aws_reset_error();
    struct aws_nitro_enclaves_rest_response *response = aws_nitro_enclaves_rest_client_request_blocking(
        client->rest_client, aws_http_method_post, aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str(target), aws_byte_cursor_from_string(request));
    int sdk_error = aws_last_error();
    aws_string_destroy(request);
    if (!response) {
        return classify_sdk_failure(sdk_error);
    }
    enum helper_status result_status = HELPER_INVALID_RESPONSE;
    struct aws_byte_buf body = {0};
    struct json_object *json = NULL;
    int status = 0;
    int64_t length = 0;
    if (!response->response || aws_http_message_get_response_status(response->response, &status)) {
        goto done;
    }
    if (status != 200) {
        result_status = classify_kms_error(status, NULL);
    }
    struct aws_input_stream *stream = aws_http_message_get_body_stream(response->response);
    if (!stream || aws_input_stream_get_length(stream, &length) || length <= 0 || length > MESSAGE_LIMIT) {
        goto done;
    }
    if (aws_byte_buf_init(&body, client->allocator, (size_t)length)) {
        result_status = HELPER_INTERNAL;
        goto done;
    }
    aws_reset_error();
    if (aws_input_stream_read(stream, &body)) {
        result_status = classify_sdk_failure(aws_last_error());
        goto done;
    }
    if (body.len != (size_t)length) {
        goto done;
    }
    json = parse_json((const char *)body.buffer, body.len);
    if (status != 200) {
        result_status = classify_kms_error(status, json);
        goto done;
    }
    *result = validated_kms_json(client->allocator, input, json);
    if (*result) {
        result_status = HELPER_OK;
    }
done:
    json_object_put(json);
    aws_byte_buf_clean_up_secure(&body);
    aws_nitro_enclaves_rest_response_destroy(response);
    return result_status;
}

/* These are the same three SDK calls used by kmstool's internal recipient
 * unwrap, with secure cleanup on every path. No application crypto parser. */
static bool unwrap_seed(struct aws_nitro_enclaves_kms_client *client, struct aws_byte_buf *envelope,
                        struct aws_byte_buf *seed) {
    struct aws_byte_buf encrypted_key = {0}, key = {0}, iv = {0}, ciphertext = {0};
    bool ok = envelope->len > 0 && envelope->len <= MESSAGE_LIMIT &&
              !aws_cms_parse_enveloped_data(envelope, &encrypted_key, &iv, &ciphertext) &&
              !aws_attestation_rsa_decrypt(client->allocator, client->keypair, &encrypted_key, &key) &&
              !aws_cms_cipher_decrypt(&ciphertext, &key, &iv, seed) && seed->len == SEED_BYTES;
    aws_byte_buf_clean_up_secure(&encrypted_key);
    aws_byte_buf_clean_up_secure(&key);
    aws_byte_buf_clean_up_secure(&iv);
    aws_byte_buf_clean_up_secure(&ciphertext);
    return ok;
}

static bool response_key_matches(const struct aws_string *key, const char *expected) {
    return key && key->len == strlen(expected) && !memcmp(key->bytes, expected, key->len);
}

static bool print_result(struct aws_allocator *allocator, const struct aws_string *response_key,
                         const char *field, const struct aws_byte_buf *value) {
    struct aws_byte_buf encoded = {0};
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(value);
    size_t capacity = 0;
    bool ok = false;
    if (aws_base64_compute_encoded_len(value->len, &capacity) ||
        aws_byte_buf_init(&encoded, allocator, capacity) || aws_base64_encode(&cursor, &encoded)) {
        goto done;
    }
    /* Emit the authoritative SDK response key, already checked against the
     * measured request. json-c escapes this public ARN; no input ARN is echoed.
     * Only recovery returns a seed; generation returns ciphertext alone. */
    struct json_object *arn = json_object_new_string_len((const char *)response_key->bytes, (int)response_key->len);
    if (!arn) {
        goto done;
    }
    const char *serialized_arn = json_object_to_json_string_ext(arn, JSON_C_TO_STRING_PLAIN);
    if (serialized_arn) {
        ok = fprintf(stdout, "{\"key_arn\":%s,\"%s\":\"%.*s\"}\n", serialized_arn, field,
                     (int)encoded.len, encoded.buffer) >= 0;
    }
    json_object_put(arn);
done:
    aws_byte_buf_clean_up_secure(&encoded);
    return ok;
}

static enum helper_status run_operation(struct aws_nitro_enclaves_kms_client *client, const struct input *input) {
    struct aws_string *json = NULL;
    enum helper_status status = call_kms(client, input, &json);
    if (status != HELPER_OK) {
        return status;
    }
    struct aws_byte_buf seed = {0};
    status = HELPER_INVALID_RESPONSE;
    if (!strcmp(input->operation, "generate")) {
        struct aws_kms_generate_data_key_response *response = aws_kms_generate_data_key_response_from_json(client->allocator, json);
        /* call_kms already checked KeyId and rejected plaintext. Validate the
         * generated Recipient envelope before permitting the first S3 write,
         * but keep its seed inside this process and wipe it below. */
        if (response && response_key_matches(response->key_id, input->key_arn) && response->ciphertext_blob.len > 0 &&
            response->ciphertext_blob.len <= CIPHERTEXT_LIMIT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            status = print_result(client->allocator, response->key_id, "ciphertext", &response->ciphertext_blob)
                         ? HELPER_OK : HELPER_INTERNAL;
        }
        aws_kms_generate_data_key_response_destroy(response);
    } else {
        struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_from_json(client->allocator, json);
        if (response && response_key_matches(response->key_id, input->key_arn) &&
            response->encryption_algorithm == AWS_EA_SYMMETRIC_DEFAULT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            status = print_result(client->allocator, response->key_id, "seed", &seed)
                         ? HELPER_OK : HELPER_INTERNAL;
        }
        aws_kms_decrypt_response_destroy(response);
    }
    aws_byte_buf_clean_up_secure(&seed);
    aws_string_destroy_secure(json);
    return status;
}

int main(int argc, char **argv) {
    (void)argv;
    struct rlimit no_core = {0, 0};
    struct rlimit address_space = {1024ULL * 1024 * 1024, 1024ULL * 1024 * 1024};
    struct rlimit cpu = {12, 12};
    /* The SDK buffers HTTP responses; bound the process as well as the parsed
     * message. Rust also caps each helper at 12 seconds and uses the remaining
     * aggregate recovery budget when that is shorter. */
    if (argc != 1) {
        return HELPER_CONFIGURATION;
    }
    if (setrlimit(RLIMIT_CORE, &no_core) || setrlimit(RLIMIT_AS, &address_space) ||
        setrlimit(RLIMIT_CPU, &cpu) || prctl(PR_SET_DUMPABLE, 0) || setvbuf(stdin, NULL, _IONBF, 0) ||
        setvbuf(stdout, NULL, _IONBF, 0)) {
        return HELPER_INTERNAL;
    }
    alarm(12);
    struct input input = {0};
    if (!read_input(&input)) {
        erase_input_credentials(input.json);
        json_object_put(input.json);
        return HELPER_CONFIGURATION;
    }
    aws_nitro_enclaves_library_init(NULL);
    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    struct aws_string *region = aws_string_new_from_c_str(allocator, input.region);
    struct aws_string *access_key = aws_string_new_from_c_str(allocator, input.access_key);
    struct aws_string *secret_key = aws_string_new_from_c_str(allocator, input.secret_key);
    struct aws_string *session_token = aws_string_new_from_c_str(allocator, input.session_token);
    erase_input_credentials(input.json);
    struct aws_socket_endpoint endpoint = {.address = "3", .port = 8003};
    struct aws_nitro_enclaves_kms_client_configuration *config = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;
    enum helper_status status = HELPER_INTERNAL;
    if (region && access_key && secret_key && session_token && !aws_nitro_enclaves_library_seed_entropy(1024)) {
        config = aws_nitro_enclaves_kms_client_config_default(region, &endpoint, AWS_SOCKET_VSOCK,
                                                            access_key, secret_key, session_token);
        if (config) {
            aws_reset_error();
            client = aws_nitro_enclaves_kms_client_new(config);
            status = client ? run_operation(client, &input) : classify_sdk_failure(aws_last_error());
        }
    }
    aws_nitro_enclaves_kms_client_destroy(client);
    if (retained_bootstrap) {
        aws_client_bootstrap_release(retained_bootstrap);
    }
    aws_nitro_enclaves_kms_client_config_destroy(config);
    aws_string_destroy(region);
    aws_string_destroy_secure(access_key);
    aws_string_destroy_secure(secret_key);
    aws_string_destroy_secure(session_token);
    aws_nitro_enclaves_library_clean_up();
    json_object_put(input.json);
    return status;
}
