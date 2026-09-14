/* RGB-swap custody adapter for the unmodified AWS Nitro Enclaves SDK for C. */
#include <aws/common/hash_table.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/internal/cms.h>
#include <aws/common/encoding.h>
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

static bool read_input(struct input *input) {
    char raw[MESSAGE_LIMIT + 1];
    size_t length = fread(raw, 1, sizeof(raw), stdin);
    if (ferror(stdin) || length == 0 || length > MESSAGE_LIMIT) {
        wipe(raw, sizeof(raw));
        return false;
    }
    input->json = parse_json(raw, length);
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
    if (json_object_object_length(input->json) != (generate ? 8 : 9)) {
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

/* The SDK's convenience methods discard response KeyId/algorithm. Use its
 * public REST and JSON APIs so these application checks precede CMS unwrap. */
static struct aws_string *call_kms(struct aws_nitro_enclaves_kms_client *client, const struct input *input) {
    struct aws_string *request = make_request(client, input);
    if (!request) {
        return NULL;
    }
    const char *target = !strcmp(input->operation, "generate") ? "TrentService.GenerateDataKey" : "TrentService.Decrypt";
    struct aws_nitro_enclaves_rest_response *response = aws_nitro_enclaves_rest_client_request_blocking(
        client->rest_client, aws_http_method_post, aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str(target), aws_byte_cursor_from_string(request));
    aws_string_destroy(request);
    if (!response) {
        return NULL;
    }
    struct aws_string *result = NULL;
    struct aws_byte_buf body = {0};
    struct json_object *json = NULL;
    int status = 0;
    int64_t length = 0;
    struct aws_input_stream *stream = aws_http_message_get_body_stream(response->response);
    if (aws_http_message_get_response_status(response->response, &status) || status != 200 || !stream ||
        aws_input_stream_get_length(stream, &length) || length <= 0 || length > MESSAGE_LIMIT ||
        aws_byte_buf_init(&body, client->allocator, (size_t)length) || aws_input_stream_read(stream, &body) ||
        body.len != (size_t)length) {
        goto done;
    }
    json = parse_json((const char *)body.buffer, body.len);
    if (!json) {
        goto done;
    }
    const char *key = string_field(json, "KeyId", 1, 128);
    if (!key || strcmp(key, input->key_arn)) {
        goto done;
    }
    struct json_object *plaintext = NULL;
    if (json_object_object_get_ex(json, "Plaintext", &plaintext)) {
        if (json_object_get_type(plaintext) != json_type_null &&
            (json_object_get_type(plaintext) != json_type_string || json_object_get_string_len(plaintext) != 0)) {
            goto done;
        }
        /* KMS may return null or an empty value with Recipient. The official
         * parser accepts absence; reject plaintext before this normalization. */
        json_object_object_del(json, "Plaintext");
    }
    result = aws_string_new_from_c_str(client->allocator, json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN));
done:
    json_object_put(json);
    aws_byte_buf_clean_up_secure(&body);
    aws_nitro_enclaves_rest_response_destroy(response);
    return result;
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

static bool print_result(struct aws_allocator *allocator, const struct input *input,
                         const char *field, const struct aws_byte_buf *value) {
    struct aws_byte_buf encoded = {0};
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(value);
    size_t capacity = 0;
    bool ok = false;
    if (aws_base64_compute_encoded_len(value->len, &capacity) ||
        aws_byte_buf_init(&encoded, allocator, capacity) || aws_base64_encode(&cursor, &encoded)) {
        goto done;
    }
    /* Escape the input ARN through json-c; output framing must not depend on
     * duplicating Rust's ARN validation. field is an operation-specific literal.
     * Only recovery returns a seed; generation returns ciphertext alone. */
    struct json_object *arn = NULL;
    json_object_object_get_ex(input->json, "key_arn", &arn);
    ok = fprintf(stdout, "{\"key_arn\":%s,\"%s\":\"%.*s\"}\n",
                 json_object_to_json_string_ext(arn, JSON_C_TO_STRING_PLAIN), field,
                 (int)encoded.len, encoded.buffer) >= 0;
done:
    aws_byte_buf_clean_up_secure(&encoded);
    return ok;
}

static bool run_operation(struct aws_nitro_enclaves_kms_client *client, const struct input *input) {
    struct aws_string *json = call_kms(client, input);
    if (!json) {
        return false;
    }
    struct aws_byte_buf seed = {0};
    bool ok = false;
    if (!strcmp(input->operation, "generate")) {
        struct aws_kms_generate_data_key_response *response = aws_kms_generate_data_key_response_from_json(client->allocator, json);
        /* call_kms already checked KeyId and rejected plaintext. Validate the
         * generated Recipient envelope before permitting the first S3 write,
         * but keep its seed inside this process and wipe it below. */
        if (response && response->ciphertext_blob.len > 0 &&
            response->ciphertext_blob.len <= CIPHERTEXT_LIMIT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            ok = print_result(client->allocator, input, "ciphertext", &response->ciphertext_blob);
        }
        aws_kms_generate_data_key_response_destroy(response);
    } else {
        struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_from_json(client->allocator, json);
        if (response && response->encryption_algorithm == AWS_EA_SYMMETRIC_DEFAULT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            ok = print_result(client->allocator, input, "seed", &seed);
        }
        aws_kms_decrypt_response_destroy(response);
    }
    aws_byte_buf_clean_up_secure(&seed);
    aws_string_destroy_secure(json);
    return ok;
}

int main(int argc, char **argv) {
    (void)argv;
    struct rlimit no_core = {0, 0};
    struct rlimit address_space = {1024ULL * 1024 * 1024, 1024ULL * 1024 * 1024};
    struct rlimit cpu = {12, 12};
    /* The SDK buffers HTTP responses; bound the process as well as the parsed
     * message. Rust also caps each helper at 12 seconds and uses the remaining
     * aggregate recovery budget when that is shorter. */
    if (argc != 1 || setrlimit(RLIMIT_CORE, &no_core) || setrlimit(RLIMIT_AS, &address_space) ||
        setrlimit(RLIMIT_CPU, &cpu) || prctl(PR_SET_DUMPABLE, 0) || setvbuf(stdin, NULL, _IONBF, 0) ||
        setvbuf(stdout, NULL, _IONBF, 0)) {
        return EXIT_FAILURE;
    }
    alarm(12);
    struct input input = {0};
    if (!read_input(&input)) {
        erase_input_credentials(input.json);
        json_object_put(input.json);
        return EXIT_FAILURE;
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
    bool ok = false;
    if (region && access_key && secret_key && session_token && !aws_nitro_enclaves_library_seed_entropy(1024)) {
        config = aws_nitro_enclaves_kms_client_config_default(region, &endpoint, AWS_SOCKET_VSOCK,
                                                            access_key, secret_key, session_token);
        if (config) {
            client = aws_nitro_enclaves_kms_client_new(config);
            if (client) {
                ok = run_operation(client, &input);
            }
        }
    }
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_client_bootstrap_release(retained_bootstrap);
    aws_nitro_enclaves_kms_client_config_destroy(config);
    aws_string_destroy(region);
    aws_string_destroy_secure(access_key);
    aws_string_destroy_secure(secret_key);
    aws_string_destroy_secure(session_token);
    aws_nitro_enclaves_library_clean_up();
    json_object_put(input.json);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
