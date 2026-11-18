#include "sqe_isa.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LABELS  4096
#define MAX_LINES   16384

typedef struct {
    char     name[64];
    uint32_t pc;
} asm_label_t;

typedef struct {
    int      line_no;
    uint32_t pc;
    uint8_t  op;
    uint8_t  rd;
    uint8_t  rs;
    uint8_t  rt;
    int32_t  imm;
    char     sym[64];
    int      has_sym;
} asm_stmt_t;

static void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static char *trim_ws(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    return s;
}

static void strip_comment(char *s) {
    for (; *s; s++) {
        if (*s == ';' || *s == '#') {
            *s = '\0';
            return;
        }
    }
}

static int parse_int32(const char *tok, int32_t *out) {
    if (tok == NULL || *tok == '\0') {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long long v = strtoll(tok, &end, 0);
    if (errno != 0 || end == tok || *end != '\0') {
        return -1;
    }
    *out = (int32_t)v;
    return 0;
}

static int parse_u32(const char *tok, uint32_t *out) {
    if (tok == NULL || *tok == '\0') {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(tok, &end, 0);
    if (errno != 0 || end == tok || *end != '\0' || v > 0xFFFFFFFFULL) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int parse_gpr(const char *tok, uint8_t *reg_out) {
    if (tok == NULL) {
        return -1;
    }
    if (strcmp(tok, "$zero") == 0) {
        *reg_out = 0;
        return 0;
    }
    if (tok[0] != '$' || (tok[1] != 'r' && tok[1] != 'R')) {
        return -1;
    }
    char *end = NULL;
    long idx = strtol(tok + 2, &end, 10);
    if (end == tok + 2 || *end != '\0' || idx < 0 || idx >= (long)SQE_NUM_GPRS) {
        return -1;
    }
    *reg_out = (uint8_t)idx;
    return 0;
}

static int parse_creg(const char *tok, uint16_t *creg_out) {
    int id = sqe_isa_creg_by_name(tok);
    if (id >= 0) {
        *creg_out = (uint16_t)id;
        return 0;
    }
    int32_t raw = 0;
    if (parse_int32(tok, &raw) == 0 && raw >= 0 && raw < (int32_t)SQE_NUM_CREGS) {
        *creg_out = (uint16_t)raw;
        return 0;
    }
    return -1;
}

static int find_label(const asm_label_t *labels, size_t nlabels, const char *name, uint32_t *pc_out) {
    const char *clean = (name[0] == '@') ? (name + 1) : name;
    for (size_t i = 0; i < nlabels; i++) {
        if (strcmp(labels[i].name, clean) == 0) {
            *pc_out = labels[i].pc;
            return 0;
        }
    }
    return -1;
}

static int next_token(char **cursor, char *buf, size_t buf_sz) {
    char *p = *cursor;
    while (*p && (isspace((unsigned char)*p) || *p == ',')) {
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return 0;
    }
    size_t i = 0;
    while (*p && !isspace((unsigned char)*p) && *p != ',') {
        if (i + 1 < buf_sz) {
            buf[i++] = *p;
        }
        p++;
    }
    buf[i] = '\0';
    *cursor = p;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.uc> <output.fw>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("fopen input");
        return 1;
    }

    asm_label_t *labels = (asm_label_t *)calloc(MAX_LABELS, sizeof(*labels));
    asm_stmt_t  *stmts  = (asm_stmt_t *)calloc(SQE_MAX_CODE_WORDS, sizeof(*stmts));
    if (labels == NULL || stmts == NULL) {
        fclose(fp);
        free(labels);
        free(stmts);
        return 1;
    }

    size_t nlabels = 0;
    size_t nstmts  = 0;
    uint32_t fw_version = SQE_FW_VERSION;
    uint32_t arch_rev   = SQE_FW_ARCH_REV;
    uint32_t fw_flags   = 1U;
    char entry_sym[64]    = "boot_entry";
    char dispatch_sym[64] = "dispatch_loop";
    char jmptbl_syms[SQE_JMPTBL_SIZE][64];
    memset(jmptbl_syms, 0, sizeof(jmptbl_syms));

    char line_buf[512];
    int line_no = 0;
    uint32_t cur_pc = 0;

    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        line_no++;
        strip_comment(line_buf);
        char *line = trim_ws(line_buf);
        if (*line == '\0') {
            continue;
        }

        /* Handle label definitions: @name: or name: */
        char *colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            char *lname = trim_ws(line);
            if (lname[0] == '@') {
                lname++;
            }
            if (*lname == '\0') {
                fprintf(stderr, "Syntax error at line %d: empty label\n", line_no);
                goto fail;
            }
            uint32_t dup_pc = 0;
            if (find_label(labels, nlabels, lname, &dup_pc) == 0) {
                fprintf(stderr, "Error at line %d: duplicate label '%s'\n", line_no, lname);
                goto fail;
            }
            if (nlabels >= MAX_LABELS) {
                fprintf(stderr, "Error at line %d: too many labels\n", line_no);
                goto fail;
            }
            snprintf(labels[nlabels].name, sizeof(labels[nlabels].name), "%s", lname);
            labels[nlabels].pc = cur_pc;
            nlabels++;

            line = trim_ws(colon + 1);
            if (*line == '\0') {
                continue;
            }
        }

        char *cur = line;
        char tok0[64], tok1[64], tok2[64], tok3[64];
        if (!next_token(&cur, tok0, sizeof(tok0))) {
            continue;
        }

        /* Assembler directives */
        if (tok0[0] == '.') {
            if (strcmp(tok0, ".version") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_u32(tok1, &fw_version) != 0) {
                    fprintf(stderr, "Error at line %d: invalid .version\n", line_no);
                    goto fail;
                }
            } else if (strcmp(tok0, ".arch") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_u32(tok1, &arch_rev) != 0) {
                    fprintf(stderr, "Error at line %d: invalid .arch\n", line_no);
                    goto fail;
                }
            } else if (strcmp(tok0, ".flags") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_u32(tok1, &fw_flags) != 0) {
                    fprintf(stderr, "Error at line %d: invalid .flags\n", line_no);
                    goto fail;
                }
            } else if (strcmp(tok0, ".entry") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1))) {
                    fprintf(stderr, "Error at line %d: missing .entry target\n", line_no);
                    goto fail;
                }
                snprintf(entry_sym, sizeof(entry_sym), "%s", tok1);
            } else if (strcmp(tok0, ".dispatch") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1))) {
                    fprintf(stderr, "Error at line %d: missing .dispatch target\n", line_no);
                    goto fail;
                }
                snprintf(dispatch_sym, sizeof(dispatch_sym), "%s", tok1);
            } else if (strcmp(tok0, ".jmptbl") == 0) {
                if (!next_token(&cur, tok1, sizeof(tok1)) || !next_token(&cur, tok2, sizeof(tok2))) {
                    fprintf(stderr, "Error at line %d: invalid .jmptbl syntax\n", line_no);
                    goto fail;
                }
                int opc = sqe_isa_pkt_by_name(tok1);
                if (opc < 0) {
                    int32_t raw_opc = -1;
                    if (parse_int32(tok1, &raw_opc) == 0 && raw_opc >= 0 && raw_opc < (int32_t)SQE_JMPTBL_SIZE) {
                        opc = (int)raw_opc;
                    }
                }
                if (opc < 0 || opc >= (int)SQE_JMPTBL_SIZE) {
                    fprintf(stderr, "Error at line %d: invalid packet opcode '%s'\n", line_no, tok1);
                    goto fail;
                }
                snprintf(jmptbl_syms[opc], sizeof(jmptbl_syms[opc]), "%s", tok2);
            } else if (strcmp(tok0, ".pad_to") == 0) {
                uint32_t pad_target = 0;
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_u32(tok1, &pad_target) != 0 ||
                    pad_target > SQE_MAX_CODE_WORDS) {
                    fprintf(stderr, "Error at line %d: invalid .pad_to target\n", line_no);
                    goto fail;
                }
                while (cur_pc < pad_target) {
                    stmts[nstmts].line_no = line_no;
                    stmts[nstmts].pc      = cur_pc++;
                    stmts[nstmts].op      = OP_NOP;
                    nstmts++;
                }
            } else {
                fprintf(stderr, "Error at line %d: unknown directive '%s'\n", line_no, tok0);
                goto fail;
            }
            continue;
        }

        /* Instruction statement */
        if (cur_pc >= SQE_MAX_CODE_WORDS) {
            fprintf(stderr, "Error at line %d: microcode exceeds %u words\n", line_no, SQE_MAX_CODE_WORDS);
            goto fail;
        }

        const sqe_op_info_t *info = sqe_isa_lookup_mnemonic(tok0);
        if (info == NULL) {
            fprintf(stderr, "Error at line %d: unknown instruction '%s'\n", line_no, tok0);
            goto fail;
        }

        asm_stmt_t *st = &stmts[nstmts];
        memset(st, 0, sizeof(*st));
        st->line_no = line_no;
        st->pc      = cur_pc++;
        st->op      = info->opcode;

        switch (info->fmt) {
            case INSN_FMT_NONE:
                break;
            case INSN_FMT_RD:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0) {
                    fprintf(stderr, "Error at line %d: expected register\n", line_no);
                    goto fail;
                }
                break;
            case INSN_FMT_RD_RS:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_gpr(tok2, &st->rs) != 0) {
                    fprintf(stderr, "Error at line %d: expected two registers\n", line_no);
                    goto fail;
                }
                break;
            case INSN_FMT_RD_RS_RT:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_gpr(tok2, &st->rs) != 0 ||
                    !next_token(&cur, tok3, sizeof(tok3)) || parse_gpr(tok3, &st->rt) != 0) {
                    fprintf(stderr, "Error at line %d: expected three registers\n", line_no);
                    goto fail;
                }
                break;
            case INSN_FMT_RD_UIMM:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_int32(tok2, &st->imm) != 0) {
                    fprintf(stderr, "Error at line %d: expected $rd, imm16\n", line_no);
                    goto fail;
                }
                break;
            case INSN_FMT_RD_RS_UIMM:
            case INSN_FMT_RD_RS_SIMM:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_gpr(tok2, &st->rs) != 0 ||
                    !next_token(&cur, tok3, sizeof(tok3)) || parse_int32(tok3, &st->imm) != 0) {
                    fprintf(stderr, "Error at line %d: expected $rd, $rs, imm16\n", line_no);
                    goto fail;
                }
                break;
            case INSN_FMT_BRANCH:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_gpr(tok2, &st->rs) != 0 ||
                    !next_token(&cur, tok3, sizeof(tok3))) {
                    fprintf(stderr, "Error at line %d: expected $rd, $rs, @target\n", line_no);
                    goto fail;
                }
                if (tok3[0] == '@' || parse_int32(tok3, &st->imm) != 0) {
                    snprintf(st->sym, sizeof(st->sym), "%s", tok3);
                    st->has_sym = 1;
                }
                break;
            case INSN_FMT_TARGET:
                if (!next_token(&cur, tok1, sizeof(tok1))) {
                    fprintf(stderr, "Error at line %d: expected @target\n", line_no);
                    goto fail;
                }
                if (tok1[0] == '@' || parse_int32(tok1, &st->imm) != 0) {
                    snprintf(st->sym, sizeof(st->sym), "%s", tok1);
                    st->has_sym = 1;
                }
                break;
            case INSN_FMT_CREAD: {
                uint16_t creg = 0;
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_gpr(tok1, &st->rd) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_creg(tok2, &creg) != 0) {
                    fprintf(stderr, "Error at line %d: expected $rd, CREG_NAME\n", line_no);
                    goto fail;
                }
                st->imm = (int32_t)creg;
                break;
            }
            case INSN_FMT_CWRITE: {
                uint16_t creg = 0;
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_creg(tok1, &creg) != 0 ||
                    !next_token(&cur, tok2, sizeof(tok2)) || parse_gpr(tok2, &st->rs) != 0) {
                    fprintf(stderr, "Error at line %d: expected CREG_NAME, $rs\n", line_no);
                    goto fail;
                }
                st->imm = (int32_t)creg;
                break;
            }
            case INSN_FMT_UIMM_ONLY:
                if (!next_token(&cur, tok1, sizeof(tok1)) || parse_int32(tok1, &st->imm) != 0) {
                    fprintf(stderr, "Error at line %d: expected immediate\n", line_no);
                    goto fail;
                }
                break;
        }
        nstmts++;
    }
    fclose(fp);
    fp = NULL;

    if (nstmts < 16U) {
        fprintf(stderr, "Error: firmware must contain at least 16 instructions\n");
        goto fail;
    }

    /* Pass 2: Resolve symbols and encode binary image */
    uint32_t entry_pc = 0;
    uint32_t dispatch_pc = 0;
    if (find_label(labels, nlabels, entry_sym, &entry_pc) != 0) {
        int32_t raw_e = 0;
        if (parse_int32(entry_sym, &raw_e) != 0 || raw_e < 0 || (uint32_t)raw_e >= (uint32_t)nstmts) {
            fprintf(stderr, "Error: unresolved .entry '%s'\n", entry_sym);
            goto fail;
        }
        entry_pc = (uint32_t)raw_e;
    }
    if (find_label(labels, nlabels, dispatch_sym, &dispatch_pc) != 0) {
        int32_t raw_d = 0;
        if (parse_int32(dispatch_sym, &raw_d) != 0 || raw_d < 0 || (uint32_t)raw_d >= (uint32_t)nstmts) {
            fprintf(stderr, "Error: unresolved .dispatch '%s'\n", dispatch_sym);
            goto fail;
        }
        dispatch_pc = (uint32_t)raw_d;
    }

    uint32_t default_illegal_pc = entry_pc;
    (void)find_label(labels, nlabels, "PKT_ILLEGAL", &default_illegal_pc);

    uint32_t jmptbl[SQE_JMPTBL_SIZE];
    for (size_t i = 0; i < SQE_JMPTBL_SIZE; i++) {
        if (jmptbl_syms[i][0] == '\0') {
            jmptbl[i] = default_illegal_pc;
            continue;
        }
        if (find_label(labels, nlabels, jmptbl_syms[i], &jmptbl[i]) != 0) {
            int32_t raw_j = 0;
            if (parse_int32(jmptbl_syms[i], &raw_j) != 0 || raw_j < 0 || (uint32_t)raw_j >= (uint32_t)nstmts) {
                fprintf(stderr, "Error: unresolved .jmptbl target '%s'\n", jmptbl_syms[i]);
                goto fail;
            }
            jmptbl[i] = (uint32_t)raw_j;
        }
    }

    size_t total_words = 8U + SQE_JMPTBL_SIZE + nstmts;
    uint8_t *img = (uint8_t *)calloc(total_words, sizeof(uint32_t));
    if (img == NULL) {
        goto fail;
    }

    for (size_t i = 0; i < SQE_JMPTBL_SIZE; i++) {
        write_u32_le(img + (8U + i) * 4U, jmptbl[i]);
    }

    for (size_t i = 0; i < nstmts; i++) {
        const asm_stmt_t *st = &stmts[i];
        const sqe_op_info_t *info = sqe_isa_lookup_op(st->op);
        uint32_t word = 0;

        if (info->fmt == INSN_FMT_RD_RS_RT) {
            word = sqe_enc_r(st->op, st->rd, st->rs, st->rt);
        } else if (info->fmt == INSN_FMT_BRANCH) {
            int32_t rel = st->imm;
            if (st->has_sym) {
                uint32_t target_pc = 0;
                if (find_label(labels, nlabels, st->sym, &target_pc) != 0) {
                    fprintf(stderr, "Error at line %d: undefined branch label '%s'\n", st->line_no, st->sym);
                    free(img);
                    goto fail;
                }
                rel = (int32_t)target_pc - ((int32_t)st->pc + 1);
            }
            if (rel < -32768 || rel > 32767) {
                fprintf(stderr, "Error at line %d: branch offset %d out of range\n", st->line_no, rel);
                free(img);
                goto fail;
            }
            word = sqe_enc_i(st->op, st->rd, st->rs, (uint16_t)(int16_t)rel);
        } else if (info->fmt == INSN_FMT_TARGET) {
            uint32_t dst_pc = (uint32_t)st->imm;
            if (st->has_sym) {
                if (find_label(labels, nlabels, st->sym, &dst_pc) != 0) {
                    fprintf(stderr, "Error at line %d: undefined target label '%s'\n", st->line_no, st->sym);
                    free(img);
                    goto fail;
                }
            }
            if (dst_pc >= (uint32_t)nstmts) {
                fprintf(stderr, "Error at line %d: target PC %u out of bounds\n", st->line_no, dst_pc);
                free(img);
                goto fail;
            }
            word = sqe_enc_i(st->op, 0, 0, (uint16_t)dst_pc);
        } else {
            word = sqe_enc_i(st->op, st->rd, st->rs, (uint16_t)(st->imm & 0xFFFF));
        }

        write_u32_le(img + (8U + SQE_JMPTBL_SIZE + i) * 4U, word);
    }

    uint32_t crc = sqe_crc32(img + 32U, (total_words - 8U) * 4U);
    write_u32_le(img + 0U,  SQE_FW_MAGIC);
    write_u32_le(img + 4U,  fw_version);
    write_u32_le(img + 8U,  (uint32_t)nstmts);
    write_u32_le(img + 12U, entry_pc);
    write_u32_le(img + 16U, dispatch_pc);
    write_u32_le(img + 20U, crc);
    write_u32_le(img + 24U, arch_rev);
    write_u32_le(img + 28U, fw_flags);

    FILE *out = fopen(argv[2], "wb");
    if (out == NULL) {
        perror("fopen output");
        free(img);
        goto fail;
    }
    size_t nw = fwrite(img, sizeof(uint32_t), total_words, out);
    fclose(out);
    free(img);
    if (nw != total_words) {
        fprintf(stderr, "Error: short write to '%s'\n", argv[2]);
        goto fail;
    }

    free(labels);
    free(stmts);
    return 0;

fail:
    if (fp != NULL) {
        fclose(fp);
    }
    free(labels);
    free(stmts);
    return 1;
}
