#include "session_broker.h"

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

static const char *sb_lookup_short_var(const sb_session_t *sess, char code) {
    switch (code) {
        case 'h':
            return sess->remote_host;
        case 't':
            return sess->term_type;
        case 'u':
            return sess->preauth_account[0] != '\0' ? sess->preauth_account : NULL;
        case 'U':
            return sb_session_getenv(sess, "USER");
        default:
            return NULL;
    }
}

static int sb_append_str(char *out, size_t out_cap, size_t *pos, const char *val) {
    if (!val) {
        return 0;
    }
    size_t n = strlen(val);
    if (*pos + n >= out_cap) {
        return -1;
    }
    memcpy(out + *pos, val, n);
    *pos += n;
    out[*pos] = '\0';
    return 0;
}

int sb_expand_invocation(const sb_session_t *sess, const char *tmpl, char *out, size_t out_cap) {
    if (!sess || !tmpl || !out || out_cap == 0) {
        return -1;
    }
    out[0] = '\0';
    size_t pos = 0;

    for (size_t i = 0; tmpl[i] != '\0';) {
        if (tmpl[i] != '%') {
            if (pos + 1 >= out_cap) {
                return -1;
            }
            out[pos++] = tmpl[i++];
            out[pos] = '\0';
            continue;
        }

        i++;
        if (tmpl[i] == '\0') {
            return -1;
        }
        if (tmpl[i] == '%') {
            if (pos + 1 >= out_cap) {
                return -1;
            }
            out[pos++] = '%';
            out[pos] = '\0';
            i++;
            continue;
        }

        if (tmpl[i] == '?') {
            i++;
            char cond_var = tmpl[i];
            if (cond_var == '\0' || tmpl[i + 1] != '{') {
                return -1;
            }
            i += 2;
            const char *then_start = tmpl + i;
            while (tmpl[i] != '\0' && tmpl[i] != '}') {
                i++;
            }
            if (tmpl[i] != '}') {
                return -1;
            }
            size_t then_len = (size_t)((tmpl + i) - then_start);
            i++;

            const char *else_start = NULL;
            size_t else_len = 0;
            if (tmpl[i] == '{') {
                i++;
                else_start = tmpl + i;
                while (tmpl[i] != '\0' && tmpl[i] != '}') {
                    i++;
                }
                if (tmpl[i] != '}') {
                    return -1;
                }
                else_len = (size_t)((tmpl + i) - else_start);
                i++;
            }

            const char *cond_val = sb_lookup_short_var(sess, cond_var);
            const char *branch = (cond_val && cond_val[0] != '\0') ? then_start : else_start;
            size_t branch_len = (cond_val && cond_val[0] != '\0') ? then_len : else_len;

            if (branch && branch_len > 0) {
                char sub_tmpl[128];
                char sub_out[256];
                if (branch_len >= sizeof(sub_tmpl)) {
                    return -1;
                }
                memcpy(sub_tmpl, branch, branch_len);
                sub_tmpl[branch_len] = '\0';
                if (sb_expand_invocation(sess, sub_tmpl, sub_out, sizeof(sub_out)) != 0) {
                    return -1;
                }
                if (sb_append_str(out, out_cap, &pos, sub_out) != 0) {
                    return -1;
                }
            }
            continue;
        }

        const char *val = sb_lookup_short_var(sess, tmpl[i++]);
        if (sb_append_str(out, out_cap, &pos, val) != 0) {
            return -1;
        }
    }
    return 0;
}
