/* Exercise credential erasure against the exact installed json-c dependency.
 * Including the adapter makes its private cleanup function testable without
 * exposing another production API or replacing any SDK behavior. */
#define main swap_kms_tool_main
#include "../main.c"
#undef main

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "input cleanup check failed at line %d\n", __LINE__); \
        return EXIT_FAILURE; \
    } \
} while (0)

/* Feed synthetic flat JSON through the real stdin parser. Pipe contents are
 * public test fixtures and fit within a single PIPE_BUF write. */
static bool accepts_input(const char *raw) {
    int fds[2];
    int original_stdin = dup(STDIN_FILENO);
    if (original_stdin < 0 || pipe(fds)) {
        abort();
    }
    size_t length = strlen(raw);
    if (length > 4096 || write(fds[1], raw, length) != (ssize_t)length ||
        dup2(fds[0], STDIN_FILENO) != STDIN_FILENO) {
        abort();
    }
    close(fds[0]);
    close(fds[1]);
    clearerr(stdin);
    struct input input = {0};
    bool accepted = read_input(&input);
    erase_input_credentials(input.json);
    json_object_put(input.json);
    if (dup2(original_stdin, STDIN_FILENO) != STDIN_FILENO) {
        abort();
    }
    close(original_stdin);
    clearerr(stdin);
    return accepted;
}

#define INPUT_FIELDS "\"region\":\"eu-west-1\",\"key_arn\":\"public-key-arn\",\"seed_id\":\"seed\"," \
                     "\"bitcoin_network\":\"bitcoin\",\"access_key_id\":\"AKID\",\"secret_access_key\":\"secret\""

int main(void) {
    const int lengths[] = {0, 1, 64, 16384, MESSAGE_LIMIT};
    const char *fields[] = {"access_key_id", "secret_access_key", "session_token"};
    char *synthetic = malloc(MESSAGE_LIMIT);
    CHECK(synthetic != NULL);
    memset(synthetic, 'x', MESSAGE_LIMIT);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        struct json_object *json = json_object_new_object();
        CHECK(json != NULL);
        const char *before[3];
        for (size_t j = 0; j < 3; j++) {
            struct json_object *value = json_object_new_string_len(synthetic, lengths[i]);
            CHECK(value != NULL);
            before[j] = json_object_get_string(value);
            CHECK(json_object_object_add(json, fields[j], value) == 0);
        }
        struct json_object *arn = json_object_new_string("unchanged-public-key-id");
        CHECK(arn != NULL && json_object_object_add(json, "key_arn", arn) == 0);
        erase_input_credentials(json);
        for (size_t j = 0; j < 3; j++) {
            struct json_object *value = NULL;
            CHECK(json_object_object_get_ex(json, fields[j], &value));
            /* Equal-length replacement must wipe the existing allocation. */
            CHECK(json_object_get_string(value) == before[j]);
            CHECK(json_object_get_string_len(value) == lengths[i]);
            for (int k = 0; k < lengths[i]; k++) {
                CHECK(before[j][k] == 0);
            }
        }
        CHECK(strcmp(json_object_get_string(arn), "unchanged-public-key-id") == 0);
        json_object_put(json);
    }
    erase_input_credentials(NULL);
    struct json_object *invalid = json_object_new_object();
    CHECK(invalid != NULL);
    CHECK(json_object_object_add(invalid, "secret_access_key", json_object_new_int(42)) == 0);
    erase_input_credentials(invalid);
    json_object_put(invalid);
    free(synthetic);
    CHECK(setvbuf(stdin, NULL, _IONBF, 0) == 0);
    const struct { const char *raw; bool accepted; } cases[] = {
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\"}", true},
        {"{\"operation\":\"decrypt\"," INPUT_FIELDS ",\"session_token\":\"\",\"ciphertext\":\"AA==\"}", true},
        {"{\"operation\":\"generate\",\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\"}", false},
        {"{\"operation\":\"generate\",\"\\u006fperation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\"}", false},
        {"{\"operation\":{\"ignored\":\"nested\"},\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\",\"session_token\":\"other\"}", false},
        {"{\"operation\":\"decrypt\"," INPUT_FIELDS ",\"session_token\":\"\",\"ciphertext\":\"AA==\",\"ciphertext\":\"AQ==\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\",\"extra\":\"field\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"colon:and\\\"quote\\\\slash\"}", true},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\u003a\\u0022\"}", true},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\ud800\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\udc00\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\ud83d\\ude00\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\u0000\"}", false},
        {"{\"operation\":\"generate\"," INPUT_FIELDS ",\"session_token\":\"\\u000a\"}", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK(accepts_input(cases[i].raw) == cases[i].accepted);
    }
    /* Official AWS credentials accept an empty optional session token. Long-term
     * credentials need none; temporary role credentials must supply their token. */
    aws_nitro_enclaves_library_init(NULL);
    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    struct aws_credentials *credentials = aws_credentials_new(
        allocator, aws_byte_cursor_from_c_str("AKID"), aws_byte_cursor_from_c_str("secret"),
        aws_byte_cursor_from_c_str(""), UINT64_MAX);
    CHECK(credentials != NULL && aws_credentials_get_session_token(credentials).len == 0);
    aws_credentials_release(credentials);
    aws_nitro_enclaves_library_clean_up();
    printf("credential cleanup, %zu strict IPC cases and optional AWS session-token checks passed\n",
           sizeof(cases) / sizeof(cases[0]));
    return EXIT_SUCCESS;
}
