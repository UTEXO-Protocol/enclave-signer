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
    puts("credential cleanup checks passed");
    return EXIT_SUCCESS;
}
