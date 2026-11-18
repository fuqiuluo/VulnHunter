#include "session_broker.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <handshake.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open input file\n");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    long fsz = ftell(fp);
    if (fsz <= 0 || fsz > 512 * 1024 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 1;
    }

    uint8_t *buf = malloc((size_t)fsz);
    if (!buf) {
        fclose(fp);
        return 1;
    }
    if (fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz) {
        free(buf);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    sb_session_t sess;
    if (sb_negotiate_stream(&sess, buf, (size_t)fsz) != 0) {
        free(buf);
        return 1;
    }
    free(buf);

    char cmdline[SB_MAX_CMD_LEN];
    if (sb_expand_invocation(&sess, SB_DEFAULT_TEMPLATE, cmdline, sizeof(cmdline)) != 0) {
        return 1;
    }

    int login_argc = 0;
    char **login_argv = NULL;
    if (sb_split_argv(cmdline, &login_argc, &login_argv) != 0) {
        return 1;
    }

    const char *ticket = sb_session_getenv(&sess, "TICKET");
    sb_auth_result_t auth;
    int rc = sb_dispatch_login(login_argc, login_argv, ticket, &auth);
    sb_free_argv(login_argc, login_argv);

    if (rc != 0 || !auth.accepted) {
        return 1;
    }

    printf("OK session=%u principal=%s role=%s preauth=%d\n",
           sess.session_id,
           auth.principal,
           auth.role,
           auth.preauthenticated ? 1 : 0);
    return 0;
}
