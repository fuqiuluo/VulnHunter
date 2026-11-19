#include "session_broker.h"

#include <ctype.h>
#include <string.h>

static void sb_put_var(sb_session_t *sess, const char *key, const char *val) {
    if (key[0] == '\0') {
        return;
    }
    for (size_t i = 0; i < sess->var_count; ++i) {
        if (strcmp(sess->vars[i].key, key) == 0) {
            strncpy(sess->vars[i].value, val, SB_MAX_VAL_LEN - 1);
            sess->vars[i].value[SB_MAX_VAL_LEN - 1] = '\0';
            return;
        }
    }
    if (sess->var_count < SB_MAX_VARS) {
        sb_kv_t *slot = &sess->vars[sess->var_count++];
        strncpy(slot->key, key, SB_MAX_KEY_LEN - 1);
        slot->key[SB_MAX_KEY_LEN - 1] = '\0';
        strncpy(slot->value, val, SB_MAX_VAL_LEN - 1);
        slot->value[SB_MAX_VAL_LEN - 1] = '\0';
    }
}

static int sb_parse_env_suboption(sb_session_t *sess, const uint8_t *payload, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        if (payload[pos] != 0x00u && payload[pos] != 0x03u) {
            return -1;
        }
        pos++;
        char key[SB_MAX_KEY_LEN] = {0};
        char val[SB_MAX_VAL_LEN] = {0};
        size_t klen = 0;
        size_t vlen = 0;

        while (pos < len && payload[pos] != 0x01u && payload[pos] != 0x00u && payload[pos] != 0x03u) {
            if (klen + 1 >= sizeof(key) || !isprint(payload[pos])) {
                return -1;
            }
            key[klen++] = (char)payload[pos++];
        }
        if (pos < len && payload[pos] == 0x01u) {
            pos++;
            while (pos < len && payload[pos] != 0x00u && payload[pos] != 0x03u) {
                if (vlen + 1 >= sizeof(val) || !isprint(payload[pos])) {
                    return -1;
                }
                val[vlen++] = (char)payload[pos++];
            }
        }
        sb_put_var(sess, key, val);
    }
    return 0;
}

int sb_negotiate_stream(sb_session_t *sess, const uint8_t *buf, size_t len) {
    if (!sess || !buf || len < 16) {
        return -1;
    }
    memset(sess, 0, sizeof(*sess));

    uint32_t magic = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                     ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    if (magic != SB_WIRE_MAGIC) {
        return -1;
    }

    sess->session_id = (uint32_t)buf[4] | ((uint32_t)buf[5] << 8) |
                       ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24);
    strcpy(sess->remote_host, "client.internal");
    strcpy(sess->term_type, "vt220");

    size_t i = 16;
    while (i < len) {
        if (buf[i] != SB_CTL_ESC) {
            i++;
            continue;
        }
        if (i + 2 >= len || buf[i + 1] != SB_CTL_SUB_BEGIN) {
            return -1;
        }
        uint8_t opt = buf[i + 2];
        i += 3;

        uint8_t subbuf[256];
        size_t sublen = 0;
        bool closed = false;

        while (i < len) {
            if (buf[i] == SB_CTL_ESC) {
                if (i + 1 >= len) {
                    return -1;
                }
                if (buf[i + 1] == SB_CTL_ESC) {
                    if (sublen >= sizeof(subbuf)) {
                        return -1;
                    }
                    subbuf[sublen++] = SB_CTL_ESC;
                    i += 2;
                    continue;
                }
                if (buf[i + 1] == SB_CTL_SUB_END) {
                    i += 2;
                    closed = true;
                    break;
                }
                return -1;
            }
            if (sublen >= sizeof(subbuf)) {
                return -1;
            }
            subbuf[sublen++] = buf[i++];
        }

        if (!closed) {
            return -1;
        }

        if (opt == SB_OPT_TERM_TYPE && sublen > 0 && sublen < sizeof(sess->term_type)) {
            memcpy(sess->term_type, subbuf, sublen);
            sess->term_type[sublen] = '\0';
        } else if (opt == SB_OPT_SESSION_ENV) {
            if (sb_parse_env_suboption(sess, subbuf, sublen) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

const char *sb_session_getenv(const sb_session_t *sess, const char *key) {
    if (!sess || !key) {
        return NULL;
    }
    for (size_t i = 0; i < sess->var_count; ++i) {
        if (strcmp(sess->vars[i].key, key) == 0) {
            return sess->vars[i].value;
        }
    }
    return NULL;
}
