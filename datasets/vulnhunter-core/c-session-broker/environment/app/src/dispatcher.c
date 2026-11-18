#include "session_broker.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int sb_split_argv(const char *cmdline, int *argc_out, char ***argv_out) {
    if (!cmdline || !argc_out || !argv_out) {
        return -1;
    }

    char **argv = calloc(32, sizeof(char *));
    if (!argv) {
        return -1;
    }

    int argc = 0;
    const char *p = cmdline;
    while (*p != '\0') {
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        if (argc >= 31) {
            sb_free_argv(argc, argv);
            return -1;
        }

        char token[SB_MAX_VAL_LEN];
        size_t tlen = 0;
        char quote = '\0';

        while (*p != '\0') {
            if (quote == '\0' && isspace((unsigned char)*p)) {
                break;
            }
            if ((*p == '\'' || *p == '"') && quote == '\0') {
                quote = *p++;
                continue;
            }
            if (*p == quote && quote != '\0') {
                quote = '\0';
                p++;
                continue;
            }
            if (tlen + 1 >= sizeof(token)) {
                sb_free_argv(argc, argv);
                return -1;
            }
            token[tlen++] = *p++;
        }

        if (quote != '\0') {
            sb_free_argv(argc, argv);
            return -1;
        }

        token[tlen] = '\0';
        argv[argc] = malloc(tlen + 1);
        if (!argv[argc]) {
            sb_free_argv(argc, argv);
            return -1;
        }
        memcpy(argv[argc], token, tlen + 1);
        argc++;
    }

    *argc_out = argc;
    *argv_out = argv;
    return 0;
}

void sb_free_argv(int argc, char **argv) {
    if (!argv) {
        return;
    }
    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    free(argv);
}

int sb_dispatch_login(int argc, char *const argv[], const char *credential_token, sb_auth_result_t *res) {
    if (argc < 1 || !argv || !res) {
        return -1;
    }
    memset(res, 0, sizeof(*res));

    bool force_preauth = false;
    const char *account = NULL;
    bool end_of_opts = false;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!end_of_opts && strcmp(arg, "--") == 0) {
            end_of_opts = true;
            continue;
        }
        if (!end_of_opts && arg[0] == '-' && arg[1] != '\0') {
            if (strcmp(arg, "-p") == 0) {
                continue;
            }
            if (strcmp(arg, "-h") == 0 || strcmp(arg, "-t") == 0) {
                if (i + 1 >= argc) {
                    return -1;
                }
                i++;
                continue;
            }
            if (strcmp(arg, "-f") == 0) {
                force_preauth = true;
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    account = argv[++i];
                }
                continue;
            }
            return -1;
        }
        if (!account) {
            account = arg;
        }
    }

    if (!account || account[0] == '\0') {
        account = "guest";
    }

    if (force_preauth) {
        res->accepted = true;
        res->preauthenticated = true;
    } else if (credential_token && strcmp(credential_token, "valid-session-ticket") == 0 &&
               strcmp(account, "root") != 0) {
        res->accepted = true;
        res->preauthenticated = false;
    } else if (strcmp(account, "guest") == 0) {
        res->accepted = true;
        res->preauthenticated = false;
    } else {
        return 1;
    }

    strncpy(res->principal, account, sizeof(res->principal) - 1);
    strcpy(res->role, strcmp(account, "root") == 0 ? "admin" : "standard");
    return 0;
}
