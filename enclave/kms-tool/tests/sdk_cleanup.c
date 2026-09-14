/* Exercise the actual linked SDK request lifecycle with deterministic failures.
 * No AWS endpoint, credentials, NSM device, or custom signing implementation.
 * Wrappers replace only failure sources and the asynchronous transport boundary.
 */
#include <aws/nitro_enclaves/rest.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_result.h>
#include <aws/io/stream.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum fault { NONE, MUTEX, CONDVAR, INPUT, REQUEST, RESPONSE, RESPONSE_MESSAGE, SIGNABLE,
             SIGN_START, SIGN_SYNC, APPLY_SYNC, MAKE_STREAM, ACTIVATE_STREAM,
             SIGN_ASYNC, STREAM_ASYNC_ERROR, STREAM_ASYNC_SUCCESS, SPURIOUS_WAKE };
static enum fault fault;
static int injected, signed_calls, released_streams, waits;
static struct aws_signable *allocated_signable;
static struct aws_http_make_request_options stream_options;
static pthread_t callback_thread;
static int thread_started;
static atomic_bool waiter_arrived;
static aws_signing_complete_fn *sign_callback;
static void *sign_userdata;
static char fake_connection, fake_stream;
#define STREAM ((struct aws_http_stream *)&fake_stream)

int __real_aws_mutex_init(struct aws_mutex *mutex);
int __wrap_aws_mutex_init(struct aws_mutex *mutex) {
    if (fault == MUTEX) { injected++; return AWS_OP_ERR; }
    return __real_aws_mutex_init(mutex);
}
int __real_aws_condition_variable_init(struct aws_condition_variable *condition);
int __wrap_aws_condition_variable_init(struct aws_condition_variable *condition) {
    if (fault == CONDVAR) { injected++; return AWS_OP_ERR; }
    return __real_aws_condition_variable_init(condition);
}
int __real_aws_condition_variable_wait(struct aws_condition_variable *, struct aws_mutex *);
int __wrap_aws_condition_variable_wait(struct aws_condition_variable *condition, struct aws_mutex *mutex) {
    waits++;
    if (fault == SPURIOUS_WAKE && waits == 1) { injected++; return AWS_OP_SUCCESS; }
    atomic_store_explicit(&waiter_arrived, true, memory_order_release);
    return __real_aws_condition_variable_wait(condition, mutex);
}
struct aws_input_stream *__real_aws_input_stream_new_from_cursor(struct aws_allocator *, const struct aws_byte_cursor *);
struct aws_input_stream *__wrap_aws_input_stream_new_from_cursor(struct aws_allocator *allocator, const struct aws_byte_cursor *cursor) {
    if (fault == INPUT) { injected++; return NULL; }
    return __real_aws_input_stream_new_from_cursor(allocator, cursor);
}
struct aws_http_message *__real_aws_http_message_new_request(struct aws_allocator *);
struct aws_http_message *__wrap_aws_http_message_new_request(struct aws_allocator *allocator) {
    if (fault == REQUEST) { injected++; return NULL; }
    return __real_aws_http_message_new_request(allocator);
}
void *__real_aws_mem_calloc(struct aws_allocator *, size_t, size_t);
void *__wrap_aws_mem_calloc(struct aws_allocator *allocator, size_t count, size_t size) {
    if (fault == RESPONSE && count == 1 && size == sizeof(struct aws_nitro_enclaves_rest_response)) {
        injected++; return NULL;
    }
    return __real_aws_mem_calloc(allocator, count, size);
}
struct aws_http_message *__real_aws_http_message_new_response(struct aws_allocator *);
struct aws_http_message *__wrap_aws_http_message_new_response(struct aws_allocator *allocator) {
    if (fault == RESPONSE_MESSAGE) { injected++; return NULL; }
    return __real_aws_http_message_new_response(allocator);
}
struct aws_signable *__real_aws_signable_new_http_request(struct aws_allocator *, struct aws_http_message *);
struct aws_signable *__wrap_aws_signable_new_http_request(struct aws_allocator *allocator, struct aws_http_message *request) {
    if (fault == SIGNABLE) { injected++; return NULL; }
    allocated_signable = __real_aws_signable_new_http_request(allocator, request);
    return allocated_signable;
}
void __real_aws_signable_destroy(struct aws_signable *);
void __wrap_aws_signable_destroy(struct aws_signable *signable) {
    /* A non-NULL uninitialized cleanup pointer is never a valid allocation. */
    CHECK(signable == allocated_signable);
    __real_aws_signable_destroy(signable);
}
void __wrap_aws_http_stream_release(struct aws_http_stream *stream) {
    CHECK(stream == NULL || stream == STREAM);
    released_streams++;
}
static void *complete_async(void *unused) {
    (void)unused;
    /* The request mutex prevents completion from publishing until the real
     * wait releases it. Scheduling delays cannot turn this into a sync case. */
    while (!atomic_load_explicit(&waiter_arrived, memory_order_acquire)) usleep(1000);
    sign_callback(NULL, fault == SIGN_ASYNC ? AWS_OP_ERR : AWS_OP_SUCCESS, sign_userdata);
    return NULL;
}
int __wrap_aws_sign_request_aws(struct aws_allocator *allocator, const struct aws_signable *signable,
    const struct aws_signing_config_base *config, aws_signing_complete_fn *complete, void *userdata) {
    (void)allocator; (void)signable; (void)config;
    signed_calls++;
    if (fault == SIGN_START) { injected++; return AWS_OP_ERR; }
    if (fault >= SIGN_ASYNC) {
        sign_callback = complete; sign_userdata = userdata;
        CHECK(pthread_create(&callback_thread, NULL, complete_async, NULL) == 0);
        thread_started = 1;
    } else {
        if (fault == SIGN_SYNC) injected++;
        complete(NULL, fault == SIGN_SYNC ? AWS_OP_ERR : AWS_OP_SUCCESS, userdata);
    }
    return AWS_OP_SUCCESS;
}
int __wrap_aws_apply_signing_result_to_http_request(struct aws_http_message *request, struct aws_allocator *allocator,
    const struct aws_signing_result *result) {
    (void)request; (void)allocator; (void)result;
    if (fault == APPLY_SYNC) { injected++; return AWS_OP_ERR; }
    return AWS_OP_SUCCESS;
}
struct aws_http_stream *__wrap_aws_http_connection_make_request(struct aws_http_connection *connection,
    const struct aws_http_make_request_options *options) {
    CHECK(connection == (struct aws_http_connection *)&fake_connection);
    if (fault == MAKE_STREAM) { injected++; return NULL; }
    stream_options = *options;
    return STREAM;
}
int __wrap_aws_http_stream_activate(struct aws_http_stream *stream) {
    CHECK(stream == STREAM);
    if (fault == ACTIVATE_STREAM) { injected++; return AWS_OP_ERR; }
    if (fault == STREAM_ASYNC_ERROR) injected++;
    stream_options.on_complete(stream, fault == STREAM_ASYNC_ERROR ? AWS_OP_ERR : AWS_OP_SUCCESS, stream_options.user_data);
    return AWS_OP_SUCCESS;
}

static void run_case(enum fault chosen) {
    alarm(3); /* An unconditional wait after a synchronous callback must fail. */
    struct aws_allocator *allocator = aws_default_allocator();
    struct aws_nitro_enclaves_rest_client client = {0};
    client.allocator = allocator;
    client.connection = (struct aws_http_connection *)&fake_connection;
    client.region = aws_string_new_from_c_str(allocator, "eu-west-1");
    client.service = aws_string_new_from_c_str(allocator, "kms");
    client.host_name = aws_string_new_from_c_str(allocator, "kms.eu-west-1.amazonaws.com");
    CHECK(client.region && client.service && client.host_name);
    fault = chosen;
    struct aws_nitro_enclaves_rest_response *response = aws_nitro_enclaves_rest_client_request_blocking(
        &client, aws_byte_cursor_from_c_str("POST"), aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str("TrentService.GenerateDataKey"), aws_byte_cursor_from_c_str("{}"));
    if (thread_started) CHECK(pthread_join(callback_thread, NULL) == 0);
    CHECK((response != NULL) == (fault == STREAM_ASYNC_SUCCESS || fault == SPURIOUS_WAKE));
    if (fault <= SIGNABLE) CHECK(signed_calls == 0);
    else CHECK(signed_calls == 1);
    if (fault == SIGN_ASYNC || fault == STREAM_ASYNC_SUCCESS) CHECK(injected == 0);
    else CHECK(injected == 1);
    if (fault == SIGN_SYNC || fault == APPLY_SYNC) CHECK(waits == 0 && released_streams == 1);
    if (fault >= SIGN_ASYNC) CHECK(waits >= 1 && released_streams == 1);
    if (fault == SPURIOUS_WAKE) CHECK(waits >= 2);
    fault = NONE;
    aws_nitro_enclaves_rest_response_destroy(response);
    aws_string_destroy(client.region);
    aws_string_destroy(client.service);
    aws_string_destroy(client.host_name);
    alarm(0);
}
int main(int argc, char **argv) {
    static const char *names[] = {"none", "mutex", "condition-variable", "request-stream", "request-message",
        "response-allocation", "response-message", "signable", "sign-start", "sign-sync", "apply-sync",
        "make-stream", "activate-stream", "sign-async", "stream-async-error", "stream-async-success", "spurious-wake"};
    setvbuf(stdout, NULL, _IOLBF, 0);
    int failures = 0, executed = 0;
    if (argc > 2) return EXIT_FAILURE;
    for (int i = MUTEX; i <= SPURIOUS_WAKE; i++) {
        if (argc == 2 && strcmp(argv[1], names[i]) != 0) continue;
        executed++;
        pid_t pid = fork(); CHECK(pid >= 0);
        if (pid == 0) { run_case((enum fault)i); exit(0); }
        int status; CHECK(waitpid(pid, &status, 0) == pid);
        int passed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        printf("%s: %s (status=%d)\n", names[i], passed ? "PASS" : "FAIL", status);
        failures += !passed;
    }
    if (executed == 0) fprintf(stderr, "unknown fault case\n");
    return failures || executed == 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
