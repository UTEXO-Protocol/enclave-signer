/* RGB-swap custody adapter for the unmodified AWS Nitro Enclaves SDK for C. */
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/internal/cms.h>
#include <aws/common/encoding.h>
#include <aws/io/stream.h>
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

/* json-c owns its parsed strings. These copies live only in this short-lived
 * process; credentials are never passed through argv, environment or files. */
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

static bool valid_key_arn(const char *arn, const char *region) {
    char prefix[64];
    int prefix_length = snprintf(prefix, sizeof(prefix), "arn:aws:kms:%s:", region);
    if (prefix_length <= 0 || (size_t)prefix_length >= sizeof(prefix) ||
        strncmp(arn, prefix, (size_t)prefix_length)) {
        return false;
    }
    const char *account = arn + prefix_length;
    if (strlen(account) < 17) {
        return false;
    }
    for (size_t i = 0; i < 12; i++) {
        if (!isdigit((unsigned char)account[i])) {
            return false;
        }
    }
    if (strncmp(account + 12, ":key/", 5)) {
        return false;
    }
    const char *id = account + 17;
    bool multi_region = !strncmp(id, "mrk-", 4);
    if (strlen(id) != 36) {
        return false;
    }
    for (size_t i = multi_region ? 4 : 0; i < 36; i++) {
        bool separator = !multi_region && (i == 8 || i == 13 || i == 18 || i == 23);
        if (separator ? id[i] != '-' : !isxdigit((unsigned char)id[i])) {
            return false;
        }
    }
    return true;
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
    size_t region_length = strlen(input->region);
    if (input->region[0] == '-' || input->region[region_length - 1] == '-' ||
        !strncmp(input->region, "cn-", 3) || !strncmp(input->region, "us-gov-", 7) ||
        !strncmp(input->region, "us-iso", 6)) {
        return false;
    }
    for (const char *c = input->region; *c; c++) {
        if (!(*c >= 'a' && *c <= 'z') && !isdigit((unsigned char)*c) && *c != '-') {
            return false;
        }
    }
    for (const char *c = input->seed_id; *c; c++) {
        if (!isalnum((unsigned char)*c) && *c != '-' && *c != '_' && *c != '.') {
            return false;
        }
    }
    for (const char *c = input->access_key; *c; c++) {
        if (!isalnum((unsigned char)*c)) {
            return false;
        }
    }
    if (strcmp(input->network, "bitcoin") && strcmp(input->network, "testnet") &&
        strcmp(input->network, "testnet4") && strcmp(input->network, "signet") &&
        strcmp(input->network, "regtest")) {
        return false;
    }
    return valid_key_arn(input->key_arn, input->region);
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

static bool print_result(struct aws_allocator *allocator, const char *key_arn, const struct aws_byte_buf *seed,
                         const struct aws_byte_buf *ciphertext) {
    struct aws_byte_buf encoded_seed = {0}, encoded_ciphertext = {0};
    struct aws_byte_cursor seed_cursor = aws_byte_cursor_from_buf(seed);
    size_t capacity = 0;
    bool ok = false;
    if (aws_base64_compute_encoded_len(seed->len, &capacity) ||
        aws_byte_buf_init(&encoded_seed, allocator, capacity) || aws_base64_encode(&seed_cursor, &encoded_seed)) {
        goto done;
    }
    if (ciphertext) {
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(ciphertext);
        if (aws_base64_compute_encoded_len(ciphertext->len, &capacity) ||
            aws_byte_buf_init(&encoded_ciphertext, allocator, capacity) || aws_base64_encode(&cursor, &encoded_ciphertext)) {
            goto done;
        }
    }
    /* The validated ARN and base64 alphabet need no JSON escaping. stdout is
     * unbuffered, avoiding another retained stdio copy of the seed. */
    if (fprintf(stdout, "{\"key_arn\":\"%s\",\"seed\":\"%.*s\"", key_arn,
                (int)encoded_seed.len, encoded_seed.buffer) < 0) {
        goto done;
    }
    if (ciphertext && fprintf(stdout, ",\"ciphertext\":\"%.*s\"", (int)encoded_ciphertext.len,
                              encoded_ciphertext.buffer) < 0) {
        goto done;
    }
    ok = fputs("}\n", stdout) >= 0;
done:
    aws_byte_buf_clean_up_secure(&encoded_seed);
    aws_byte_buf_clean_up_secure(&encoded_ciphertext);
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
        if (response && response->key_id && !strcmp(aws_string_c_str(response->key_id), input->key_arn) &&
            response->plaintext.len == 0 && response->ciphertext_blob.len > 0 &&
            response->ciphertext_blob.len <= CIPHERTEXT_LIMIT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            ok = print_result(client->allocator, input->key_arn, &seed, &response->ciphertext_blob);
        }
        aws_kms_generate_data_key_response_destroy(response);
    } else {
        struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_from_json(client->allocator, json);
        if (response && response->key_id && !strcmp(aws_string_c_str(response->key_id), input->key_arn) &&
            response->plaintext.len == 0 && response->encryption_algorithm == AWS_EA_SYMMETRIC_DEFAULT &&
            unwrap_seed(client, &response->ciphertext_for_recipient, &seed)) {
            ok = print_result(client->allocator, input->key_arn, &seed, NULL);
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
    struct rlimit cpu = {30, 30};
    /* The SDK buffers HTTP responses; bound the process as well as the parsed
     * message. Rust independently enforces a 40-second timeout and pipe cap. */
    if (argc != 1 || setrlimit(RLIMIT_CORE, &no_core) || setrlimit(RLIMIT_AS, &address_space) ||
        setrlimit(RLIMIT_CPU, &cpu) || prctl(PR_SET_DUMPABLE, 0) || setvbuf(stdout, NULL, _IONBF, 0)) {
        return EXIT_FAILURE;
    }
    alarm(35);
    struct input input = {0};
    if (!read_input(&input)) {
        json_object_put(input.json);
        return EXIT_FAILURE;
    }
    aws_nitro_enclaves_library_init(NULL);
    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    struct aws_string *region = aws_string_new_from_c_str(allocator, input.region);
    struct aws_string *access_key = aws_string_new_from_c_str(allocator, input.access_key);
    struct aws_string *secret_key = aws_string_new_from_c_str(allocator, input.secret_key);
    struct aws_string *session_token = aws_string_new_from_c_str(allocator, input.session_token);
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
    aws_nitro_enclaves_kms_client_config_destroy(config);
    aws_string_destroy(region);
    aws_string_destroy_secure(access_key);
    aws_string_destroy_secure(secret_key);
    aws_string_destroy_secure(session_token);
    aws_nitro_enclaves_library_clean_up();
    json_object_put(input.json);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
