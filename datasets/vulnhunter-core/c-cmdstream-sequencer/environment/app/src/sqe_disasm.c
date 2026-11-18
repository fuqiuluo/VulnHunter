#include "sqe_isa.h"
#include "sqe_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <firmware.fw> [output.uc]\n", argv[0]);
        return 1;
    }

    sqe_vm_t vm;
    if (sqe_vm_init(&vm) != SQE_OK) {
        fprintf(stderr, "Error: failed to initialize disassembler context\n");
        return 1;
    }

    sqe_status_t st = sqe_vm_load_firmware_file(&vm, argv[1]);
    if (st != SQE_OK) {
        fprintf(stderr, "Error: invalid or unreadable firmware '%s' (status=%d)\n", argv[1], (int)st);
        sqe_vm_destroy(&vm);
        return 1;
    }

    FILE *out = stdout;
    if (argc == 3) {
        out = fopen(argv[2], "w");
        if (out == NULL) {
            perror("fopen");
            sqe_vm_destroy(&vm);
            return 1;
        }
    }

    uint32_t nwords = vm.fw_hdr.code_words;
    char (*labels)[48] = (char (*)[48])calloc(nwords, sizeof(*labels));
    if (labels == NULL) {
        if (out != stdout) fclose(out);
        sqe_vm_destroy(&vm);
        return 1;
    }

    /* Pass 1: Discover symbolic entry, jump-table, subroutine, and branch labels */
    snprintf(labels[vm.fw_hdr.entry_pc], 48, "boot_entry");
    if (labels[vm.fw_hdr.dispatch_pc][0] == '\0') {
        snprintf(labels[vm.fw_hdr.dispatch_pc], 48, "dispatch_loop");
    }

    for (uint32_t opc = 0; opc < SQE_JMPTBL_SIZE; opc++) {
        uint32_t target = vm.fw_hdr.jmptbl[opc];
        if (target < nwords && labels[target][0] == '\0') {
            const char *pname = sqe_isa_pkt_name((uint8_t)opc);
            if (pname != NULL) {
                snprintf(labels[target], 48, "%s", pname);
            } else {
                snprintf(labels[target], 48, "pkt_%02x", opc);
            }
        }
    }

    for (uint32_t pc = 0; pc < nwords; pc++) {
        uint32_t insn = vm.code[pc];
        uint8_t op = sqe_dec_op(insn);
        const sqe_op_info_t *info = sqe_isa_lookup_op(op);
        if (info == NULL) {
            continue;
        }
        if (op == OP_CALL) {
            uint16_t dst = sqe_dec_uimm(insn);
            if (dst < nwords && labels[dst][0] == '\0') {
                snprintf(labels[dst], 48, "sub_%04x", dst);
            }
        } else if (op == OP_JMP) {
            uint16_t dst = sqe_dec_uimm(insn);
            if (dst < nwords && labels[dst][0] == '\0') {
                snprintf(labels[dst], 48, "L_%04x", dst);
            }
        } else if (info->fmt == INSN_FMT_BRANCH) {
            int32_t dst = (int32_t)pc + 1 + (int32_t)sqe_dec_simm(insn);
            if (dst >= 0 && (uint32_t)dst < nwords && labels[dst][0] == '\0') {
                snprintf(labels[dst], 48, "L_%04x", (unsigned)dst);
            }
        }
    }

    /* Pass 2: Emit re-assemblable microcode source */
    fprintf(out, "; QRISC-32 Sequencer Firmware Disassembly\n");
    fprintf(out, "; Code words: %u (%u bytes total image)\n\n",
            nwords, (unsigned)((8U + SQE_JMPTBL_SIZE + nwords) * 4U));
    fprintf(out, ".version  0x%08x\n", vm.fw_hdr.fw_version);
    fprintf(out, ".arch     0x%08x\n", vm.fw_hdr.arch_rev);
    fprintf(out, ".flags    0x%08x\n", vm.fw_hdr.flags);
    fprintf(out, ".entry    @%s\n", labels[vm.fw_hdr.entry_pc]);
    fprintf(out, ".dispatch @%s\n\n", labels[vm.fw_hdr.dispatch_pc]);

    for (uint32_t opc = 0; opc < SQE_JMPTBL_SIZE; opc++) {
        uint32_t target = vm.fw_hdr.jmptbl[opc];
        const char *pname = sqe_isa_pkt_name((uint8_t)opc);
        fprintf(out, ".jmptbl 0x%02x @%-28s ; %s\n",
                opc, labels[target], pname ? pname : "RESERVED");
    }

    for (uint32_t pc = 0; pc < nwords; pc++) {
        if (labels[pc][0] != '\0') {
            fprintf(out, "\n@%s:\n", labels[pc]);
        }

        uint32_t insn = vm.code[pc];
        uint8_t op   = sqe_dec_op(insn);
        uint8_t rd   = sqe_dec_rd(insn);
        uint8_t rs   = sqe_dec_rs(insn);
        uint8_t rt   = sqe_dec_rt(insn);
        uint16_t u16 = sqe_dec_uimm(insn);
        int16_t s16  = sqe_dec_simm(insn);

        const sqe_op_info_t *info = sqe_isa_lookup_op(op);
        if (info == NULL) {
            fprintf(out, "    nop ; raw=0x%08x\n", insn);
            continue;
        }

        switch (info->fmt) {
            case INSN_FMT_NONE:
                fprintf(out, "    %-8s                            ; [%04x]\n",
                        info->mnemonic, pc);
                break;
            case INSN_FMT_RD:
                fprintf(out, "    %-8s $r%02u                       ; [%04x]\n",
                        info->mnemonic, rd, pc);
                break;
            case INSN_FMT_RD_RS:
                fprintf(out, "    %-8s $r%02u, $r%02u                 ; [%04x]\n",
                        info->mnemonic, rd, rs, pc);
                break;
            case INSN_FMT_RD_RS_RT:
                fprintf(out, "    %-8s $r%02u, $r%02u, $r%02u           ; [%04x]\n",
                        info->mnemonic, rd, rs, rt, pc);
                break;
            case INSN_FMT_RD_UIMM:
                fprintf(out, "    %-8s $r%02u, 0x%04x               ; [%04x]\n",
                        info->mnemonic, rd, u16, pc);
                break;
            case INSN_FMT_RD_RS_UIMM:
                fprintf(out, "    %-8s $r%02u, $r%02u, 0x%04x         ; [%04x]\n",
                        info->mnemonic, rd, rs, u16, pc);
                break;
            case INSN_FMT_RD_RS_SIMM:
                fprintf(out, "    %-8s $r%02u, $r%02u, %d             ; [%04x]\n",
                        info->mnemonic, rd, rs, (int)s16, pc);
                break;
            case INSN_FMT_BRANCH: {
                int32_t dst = (int32_t)pc + 1 + (int32_t)s16;
                if (dst >= 0 && (uint32_t)dst < nwords && labels[dst][0] != '\0') {
                    fprintf(out, "    %-8s $r%02u, $r%02u, @%-14s ; [%04x]\n",
                            info->mnemonic, rd, rs, labels[dst], pc);
                } else {
                    fprintf(out, "    %-8s $r%02u, $r%02u, %d             ; [%04x]\n",
                            info->mnemonic, rd, rs, (int)s16, pc);
                }
                break;
            }
            case INSN_FMT_TARGET:
                if (u16 < nwords && labels[u16][0] != '\0') {
                    fprintf(out, "    %-8s @%-26s ; [%04x]\n",
                            info->mnemonic, labels[u16], pc);
                } else {
                    fprintf(out, "    %-8s 0x%04x                     ; [%04x]\n",
                            info->mnemonic, u16, pc);
                }
                break;
            case INSN_FMT_CREAD: {
                const char *cname = sqe_isa_creg_name(u16);
                if (cname != NULL) {
                    fprintf(out, "    %-8s $r%02u, %-20s ; [%04x]\n",
                            info->mnemonic, rd, cname, pc);
                } else {
                    fprintf(out, "    %-8s $r%02u, 0x%04x               ; [%04x]\n",
                            info->mnemonic, rd, u16, pc);
                }
                break;
            }
            case INSN_FMT_CWRITE: {
                const char *cname = sqe_isa_creg_name(u16);
                if (cname != NULL) {
                    fprintf(out, "    %-8s %-20s, $r%02u ; [%04x]\n",
                            info->mnemonic, cname, rs, pc);
                } else {
                    fprintf(out, "    %-8s 0x%04x, $r%02u               ; [%04x]\n",
                            info->mnemonic, u16, rs, pc);
                }
                break;
            }
            case INSN_FMT_UIMM_ONLY:
                fprintf(out, "    %-8s 0x%04x                     ; [%04x]\n",
                        info->mnemonic, u16, pc);
                break;
        }
    }

    free(labels);
    if (out != stdout) {
        fclose(out);
    }
    sqe_vm_destroy(&vm);
    return 0;
}
