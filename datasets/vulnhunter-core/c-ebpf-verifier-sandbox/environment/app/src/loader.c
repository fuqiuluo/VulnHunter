#include "bpf_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *buf; size_t len, pos; } ByteReader;

static bool rd_bytes(ByteReader *r, void *dst, size_t n) {
    if (r->pos + n > r->len) return false;
    if (n > 0) memcpy(dst, r->buf + r->pos, n);
    r->pos += n;
    return true;
}

static bool rd_u16(ByteReader *r, uint16_t *out) {
    uint8_t b[2];
    if (!rd_bytes(r, b, 2)) return false;
    *out = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
    return true;
}

static bool rd_u32(ByteReader *r, uint32_t *out) {
    uint8_t b[4];
    if (!rd_bytes(r, b, 4)) return false;
    *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return true;
}

void bpf_suite_free(BpfSuite *suite) {
    if (!suite || !suite->cases) return;
    for (uint32_t i = 0; i < suite->case_cnt; i++) {
        BpfSuiteCase *c = &suite->cases[i];
        free(c->insns);
        free(c->pkt_init);
        if (c->seed_bufs) {
            for (uint32_t s = 0; s < c->num_seeds; s++) free(c->seed_bufs[s]);
            free(c->seed_bufs);
        }
        free(c->seeds);
    }
    free(suite->cases);
    suite->cases = NULL;
    suite->case_cnt = 0;
}

int bpf_suite_load_file(const char *path, BpfSuite *out_suite, char *err_buf, size_t err_cap) {
    memset(out_suite, 0, sizeof(*out_suite));
    FILE *fp = fopen(path, "rb");
    if (!fp) { snprintf(err_buf, err_cap, "cannot open '%s'", path); return -1; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); snprintf(err_buf, err_cap, "fseek failed"); return -1; }
    long fsz = ftell(fp);
    if (fsz < 12 || fsz > (16L * 1024L * 1024L)) { fclose(fp); snprintf(err_buf, err_cap, "bad file size"); return -1; }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)fsz);
    if (!raw || fread(raw, 1, (size_t)fsz, fp) != (size_t)fsz) {
        free(raw); fclose(fp); snprintf(err_buf, err_cap, "read failed"); return -1;
    }
    fclose(fp);

    ByteReader r = { raw, (size_t)fsz, 0 };
    uint32_t magic = 0, version = 0, case_cnt = 0;
    if (!rd_u32(&r, &magic) || !rd_u32(&r, &version) || !rd_u32(&r, &case_cnt) ||
        magic != BPFS_MAGIC || version != BPFS_VERSION || case_cnt == 0 || case_cnt > 256u) {
        free(raw); snprintf(err_buf, err_cap, "invalid BPFS header"); return -1;
    }

    out_suite->case_cnt = case_cnt;
    out_suite->cases = (BpfSuiteCase *)calloc(case_cnt, sizeof(BpfSuiteCase));
    if (!out_suite->cases) { free(raw); snprintf(err_buf, err_cap, "oom"); return -1; }

    for (uint32_t i = 0; i < case_cnt; i++) {
        BpfSuiteCase *c = &out_suite->cases[i];
        uint16_t name_len = 0;
        if (!rd_u16(&r, &name_len) || name_len == 0 || name_len >= sizeof(c->name) ||
            !rd_bytes(&r, c->name, name_len)) {
            bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "bad case name"); return -1;
        }
        c->name[name_len] = '\0';

        if (!rd_u32(&r, &c->insn_cnt) || !rd_u32(&r, &c->num_maps) ||
            !rd_u32(&r, &c->pkt_init_len) || !rd_u32(&r, &c->num_seeds) ||
            c->insn_cnt == 0 || c->insn_cnt > BPF_MAX_INSNS || c->num_maps > BPF_MAX_MAPS ||
            c->pkt_init_len > BPF_MAX_PKT_SIZE || c->num_seeds > 256u) {
            bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "bad case header"); return -1;
        }

        for (uint32_t m = 0; m < c->num_maps; m++) {
            if (!rd_u32(&r, &c->maps[m].key_size) || !rd_u32(&r, &c->maps[m].value_size) ||
                !rd_u32(&r, &c->maps[m].max_entries)) {
                bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "bad map def"); return -1;
            }
        }

        c->insns = (BpfInsn *)calloc(c->insn_cnt, sizeof(BpfInsn));
        if (!c->insns) { bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "oom"); return -1; }
        for (uint32_t k = 0; k < c->insn_cnt; k++) {
            uint8_t op_regs[2]; uint16_t uoff = 0; uint32_t uimm = 0;
            if (!rd_bytes(&r, op_regs, 2) || !rd_u16(&r, &uoff) || !rd_u32(&r, &uimm)) {
                bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "truncated insns"); return -1;
            }
            c->insns[k].opcode = op_regs[0];
            c->insns[k].dst_reg = (uint8_t)(op_regs[1] & 0x0fu);
            c->insns[k].src_reg = (uint8_t)((op_regs[1] >> 4) & 0x0fu);
            c->insns[k].off = (int16_t)uoff;
            c->insns[k].imm = (int32_t)uimm;
        }

        if (c->pkt_init_len > 0u) {
            c->pkt_init = (uint8_t *)malloc(c->pkt_init_len);
            if (!c->pkt_init || !rd_bytes(&r, c->pkt_init, c->pkt_init_len)) {
                bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "truncated pkt"); return -1;
            }
        }

        if (c->num_seeds > 0u) {
            c->seeds = (BpfMapSeed *)calloc(c->num_seeds, sizeof(BpfMapSeed));
            c->seed_bufs = (uint8_t **)calloc(c->num_seeds, sizeof(uint8_t *));
            if (!c->seeds || !c->seed_bufs) { bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "oom"); return -1; }
            for (uint32_t s = 0; s < c->num_seeds; s++) {
                uint32_t mid = 0, key = 0, vlen = 0;
                if (!rd_u32(&r, &mid) || !rd_u32(&r, &key) || !rd_u32(&r, &vlen) || vlen > BPF_MAX_MAP_VALUE_SIZE) {
                    bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "bad seed"); return -1;
                }
                if (vlen > 0u) {
                    c->seed_bufs[s] = (uint8_t *)malloc(vlen);
                    if (!c->seed_bufs[s] || !rd_bytes(&r, c->seed_bufs[s], vlen)) {
                        bpf_suite_free(out_suite); free(raw); snprintf(err_buf, err_cap, "truncated seed"); return -1;
                    }
                }
                c->seeds[s] = (BpfMapSeed){ mid, key, c->seed_bufs[s], vlen };
            }
        }
    }
    free(raw);
    return 0;
}
