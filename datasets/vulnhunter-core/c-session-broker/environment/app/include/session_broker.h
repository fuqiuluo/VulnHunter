#ifndef SESSION_BROKER_H
#define SESSION_BROKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SB_WIRE_MAGIC      0x5342524Bu /* "SBRK" */
#define SB_MAX_VARS        16
#define SB_MAX_KEY_LEN     32
#define SB_MAX_VAL_LEN     128
#define SB_MAX_CMD_LEN     512

#define SB_CTL_ESC         0xFEu
#define SB_CTL_SUB_BEGIN   0xF0u
#define SB_CTL_SUB_END     0xF1u
#define SB_OPT_TERM_TYPE   0x18u
#define SB_OPT_SESSION_ENV 0x27u

#define SB_DEFAULT_TEMPLATE "session-login -p -h %h -t %t -- %?u{%u}{%U}"

typedef struct {
    char key[SB_MAX_KEY_LEN];
    char value[SB_MAX_VAL_LEN];
} sb_kv_t;

typedef struct {
    uint32_t session_id;
    char remote_host[64];
    char term_type[32];
    char preauth_account[64];
    sb_kv_t vars[SB_MAX_VARS];
    size_t var_count;
} sb_session_t;

typedef struct {
    bool accepted;
    bool preauthenticated;
    char principal[64];
    char role[32];
} sb_auth_result_t;

int sb_negotiate_stream(sb_session_t *sess, const uint8_t *buf, size_t len);
const char *sb_session_getenv(const sb_session_t *sess, const char *key);
int sb_expand_invocation(const sb_session_t *sess, const char *tmpl, char *out, size_t out_cap);
int sb_split_argv(const char *cmdline, int *argc_out, char ***argv_out);
void sb_free_argv(int argc, char **argv);
int sb_dispatch_login(int argc, char *const argv[], const char *credential_token, sb_auth_result_t *res);

#endif /* SESSION_BROKER_H */
