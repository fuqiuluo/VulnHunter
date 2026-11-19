#!/usr/bin/env python3
"""Deterministic protocol & memory-safety verifier for task: c-ike-key-schedule."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import resource
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

KEX_TRACE_MAGIC = 0x4B455831
KEX_VERSION_20 = 0x20
KEX_HDR_LEN = 28

KEX_EXCH_SA_INIT = 34
KEX_EXCH_AUTH = 35
KEX_EXCH_CREATE_CHILD = 36
KEX_EXCH_INFORMATIONAL = 37
KEX_EXCH_INTERMEDIATE = 43

KEX_FLAG_INITIATOR = 0x08
KEX_FLAG_RESPONSE = 0x20
KEX_FLAG_FRAGMENTED = 0x40

KEX_UNIT_SA_PROPOSAL = 1
KEX_UNIT_KE_CLASSIC = 2
KEX_UNIT_KEM_DATA = 3
KEX_UNIT_NONCE = 4
KEX_UNIT_ID = 5
KEX_UNIT_AUTH = 6
KEX_UNIT_NOTIFY = 7
KEX_UNIT_DELETE = 8
KEX_UNIT_SK = 46
KEX_UNIT_SKF = 53

KEX_DH_MODP256 = 1
KEX_PRF_HMAC_SHA256 = 1
KEX_AEAD_SHA256_128 = 1

KEX_KEM_NONE = 0
KEX_KEM_MLKEM768 = 1
KEX_KEM_HYBRID_DUAL = 2

KEX_POLICY_CLASSIC_ONLY = 0x0001
KEX_POLICY_HYBRID_OPTIONAL = 0x0002
KEX_POLICY_HYBRID_REQUIRED = 0x0004

KEX_AUTH_METHOD_PSK = 2

KEX_NOTIFY_NO_PROPOSAL_CHOSEN = 14
KEX_NOTIFY_TEMP_FAILURE = 43
KEX_NOTIFY_REKEY_SA = 16393
KEX_NOTIFY_INTERMEDIATE_CTX = 16400

KEX_PROTO_IKE = 1
KEX_PROTO_CHILD = 3

KEX_TRACE_OP_RECV_PKT = 1
KEX_TRACE_OP_LOCAL_REKEY_INIT = 2
KEX_TRACE_OP_DATA_PROBE = 3

P_CLASSIC = (1 << 256) - 189
P_KEM_R1 = (1 << 256) - 357
P_KEM_R2 = (1 << 256) - 617

TARGET_FILES = {"state_machine.c", "rekey.c", "frag.c"}


class Drbg:
    def __init__(self, seed: int) -> None:
        self.seed = seed & 0xFFFFFFFF
        self.counter = 0

    def generate(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            msg = struct.pack(">II", self.seed, self.counter)
            self.counter = (self.counter + 1) & 0xFFFFFFFF
            blk = hmac.new(b"KEX-DRBG-V2", msg, hashlib.sha256).digest()
            out.extend(blk[: length - len(out)])
        return bytes(out)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = bytearray()
    t = b""
    ctr = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([ctr]))
        out.extend(t[: length - len(out)])
        ctr += 1
    return bytes(out)


def clamp_scalar(raw: bytes) -> int:
    b = bytearray(raw)
    b[0] &= 0x7F
    b[31] |= 0x02
    return int.from_bytes(b, "big")


def dh_keypair_from_drbg(drbg: Drbg) -> tuple[bytes, bytes]:
    priv = bytearray(drbg.generate(32))
    priv[0] &= 0x7F
    priv[31] |= 0x02
    pub = pow(5, int.from_bytes(priv, "big"), P_CLASSIC).to_bytes(32, "big")
    return bytes(priv), pub


def dh_shared(priv: bytes, peer_pub: bytes) -> bytes:
    return pow(int.from_bytes(peer_pub, "big"), clamp_scalar(priv), P_CLASSIC).to_bytes(32, "big")


def kem_keypair(priv_seed: bytes, round_num: int) -> tuple[bytes, bytes]:
    mod_p = P_KEM_R1 if round_num == 1 else P_KEM_R2
    sk = bytearray(priv_seed)
    sk[0] &= 0x7F
    sk[31] |= 0x02
    pk = pow(5, int.from_bytes(sk, "big"), mod_p).to_bytes(32, "big")
    return bytes(sk), pk


def kem_encaps_sim(drbg: Drbg, round_num: int, peer_pk: bytes) -> tuple[bytes, bytes]:
    mod_p = P_KEM_R1 if round_num == 1 else P_KEM_R2
    eph_raw = bytearray(drbg.generate(32))
    eph_raw[0] &= 0x7F
    eph_raw[31] |= 0x02
    eph = int.from_bytes(eph_raw, "big")
    ct = pow(5, eph, mod_p).to_bytes(32, "big")
    dh = pow(int.from_bytes(peer_pk, "big"), eph, mod_p).to_bytes(32, "big")
    ss = sha256(b"KEX-KEM-V2" + struct.pack(">H", round_num) + peer_pk + ct + dh)
    return ct, ss


def stream_xor(sk_e: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    blk = 0
    pos = 0
    while pos < len(data):
        ks = hmac_sha256(sk_e, iv + struct.pack(">I", blk))
        blk += 1
        chunk = data[pos : pos + 32]
        out.extend(x ^ y for x, y in zip(chunk, ks))
        pos += len(chunk)
    return bytes(out)


def aead_seal(sk_e: bytes, sk_a: bytes, aad: bytes, iv: bytes, plain: bytes) -> bytes:
    ct = stream_xor(sk_e, iv, plain) if plain else b""
    mac_in = struct.pack(">I", len(aad)) + aad + iv + struct.pack(">I", len(ct)) + ct
    tag = hmac_sha256(sk_a, mac_in)[:16]
    return iv + ct + tag


def pack_header(init_spi: int, resp_spi: int, exch_type: int, flags: int, first_unit: int, msg_id: int, total_len: int) -> bytes:
    return struct.pack(">QQBBBBII", init_spi, resp_spi, KEX_VERSION_20, exch_type, flags, first_unit, msg_id, total_len)


def pack_unit(utype: int, body: bytes, critical: int = 0) -> bytes:
    return struct.pack(">BBH", utype, critical, 4 + len(body)) + body


def pack_proposal(dh_group: int, policy_flags: int, child_spi: int, kem_alg: int = 0) -> bytes:
    body = struct.pack(">HHHH I HH", dh_group, KEX_PRF_HMAC_SHA256, KEX_AEAD_SHA256_128, policy_flags, child_spi, kem_alg, 0)
    return pack_unit(KEX_UNIT_SA_PROPOSAL, body)


def pack_ke(pub: bytes, dh_group: int = KEX_DH_MODP256) -> bytes:
    return pack_unit(KEX_UNIT_KE_CLASSIC, struct.pack(">HH", dh_group, 0) + pub)


def pack_kem(round_num: int, kem_alg: int, blob: bytes) -> bytes:
    return pack_unit(KEX_UNIT_KEM_DATA, struct.pack(">HH", round_num, kem_alg) + blob)


def pack_nonce(nonce: bytes) -> bytes:
    return pack_unit(KEX_UNIT_NONCE, nonce)


def pack_id(id_val: int) -> bytes:
    return pack_unit(KEX_UNIT_ID, struct.pack(">II", 1, id_val))


def pack_auth(mac: bytes) -> bytes:
    return pack_unit(KEX_UNIT_AUTH, struct.pack(">HH", KEX_AUTH_METHOD_PSK, 0) + mac)


def pack_notify(notify_type: int, proto_id: int, aux_u32: int, extra: bytes = b"") -> bytes:
    spi_sz = 4 if aux_u32 != 0 else 0
    return pack_unit(KEX_UNIT_NOTIFY, struct.pack(">HBBI", notify_type, proto_id, spi_sz, aux_u32) + extra)


def pack_delete(proto_id: int, spi: int, count: int = 1) -> bytes:
    return pack_unit(KEX_UNIT_DELETE, struct.pack(">HHI", proto_id, count, spi))


def wrap_sk_packet(init_spi: int, resp_spi: int, exch_type: int, flags: int, msg_id: int, inner_first: int, plain: bytes, sk_e: bytes, sk_a: bytes, iv: bytes) -> bytes:
    sk_body_len = 4 + 8 + len(plain) + 16
    total_len = KEX_HDR_LEN + 4 + sk_body_len
    hdr = pack_header(init_spi, resp_spi, exch_type, flags, KEX_UNIT_SK, msg_id, total_len)
    sealed = aead_seal(sk_e, sk_a, hdr, iv, plain)
    sk_unit = pack_unit(KEX_UNIT_SK, bytes([inner_first, 0, 0, 0]) + sealed)
    return hdr + sk_unit


def wrap_skf_packet(init_spi: int, resp_spi: int, exch_type: int, flags: int, msg_id: int, frag_num: int, total_frags: int, inner_first: int, chunk: bytes, sk_e: bytes, sk_a: bytes, iv: bytes) -> bytes:
    frag_meta = struct.pack(">HHBBBB", frag_num, total_frags, inner_first, 0, 0, 0)
    skf_body_len = 8 + 8 + len(chunk) + 16
    total_len = KEX_HDR_LEN + 4 + skf_body_len
    hdr = pack_header(init_spi, resp_spi, exch_type, flags | KEX_FLAG_FRAGMENTED, KEX_UNIT_SKF, msg_id, total_len)
    sealed = aead_seal(sk_e, sk_a, hdr + frag_meta, iv, chunk)
    return hdr + pack_unit(KEX_UNIT_SKF, frag_meta + sealed)


def update_int_auth(chain: bytes, init_spi: int, resp_spi: int, exch_type: int, flags: int, msg_id: int, inner: bytes) -> bytes:
    clean_flags = flags & (KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE)
    meta = struct.pack(">QQBBBBII", init_spi, resp_spi, KEX_VERSION_20, exch_type, clean_flags, 0, msg_id, len(inner))
    return sha256(chain + meta + inner)


def compute_auth_mac(sk_p: bytes, psk: bytes, init_hash: bytes, peer_nonce: bytes, id_val: int, int_auth_i: bytes | None, int_auth_r: bytes | None, int_rounds: int) -> bytes:
    id_prf = hmac_sha256(sk_p, struct.pack(">II", 1, id_val))
    body = init_hash + peer_nonce + id_prf
    if int_rounds > 0 and int_auth_i is not None and int_auth_r is not None:
        int_blk = int_auth_i + int_auth_r + struct.pack(">H", int_rounds)
        body += hmac_sha256(sk_p, int_blk)
    return hmac_sha256(psk, body)


def derive_ike_keys(nonce_i: bytes, nonce_r: bytes, dh_ss: bytes, init_spi: int, resp_spi: int) -> dict[str, bytes]:
    skeyseed = hkdf_extract(nonce_i + nonce_r, dh_ss)
    info = b"KEX-IKE-KEYS" + nonce_i + nonce_r + struct.pack(">QQ", init_spi, resp_spi)
    ks = hkdf_expand(skeyseed, info, 224)
    names = ("sk_d", "sk_ai", "sk_ar", "sk_ei", "sk_er", "sk_pi", "sk_pr")
    return {name: ks[i * 32 : (i + 1) * 32] for i, name in enumerate(names)}


def reseed_ike_keys(old_sk_d: bytes, round_num: int, pq_ss: bytes, nonce_i: bytes, nonce_r: bytes, init_spi: int, resp_spi: int) -> dict[str, bytes]:
    skeyseed = hkdf_extract(old_sk_d, pq_ss + nonce_i + nonce_r)
    info = b"KEX-HYB-KEYS" + struct.pack(">H", round_num) + nonce_i + nonce_r + struct.pack(">QQ", init_spi, resp_spi)
    ks = hkdf_expand(skeyseed, info, 224)
    names = ("sk_d", "sk_ai", "sk_ar", "sk_ei", "sk_er", "sk_pi", "sk_pr")
    return {name: ks[i * 32 : (i + 1) * 32] for i, name in enumerate(names)}


def derive_child_keys(sk_d: bytes, nonce_i: bytes, nonce_r: bytes, spi_in: int, spi_out: int, pfs_ss: bytes | None = None) -> tuple[bytes, bytes]:
    ikm = (pfs_ss or b"") + nonce_i + nonce_r
    prk = hkdf_extract(sk_d, ikm)
    info = b"KEX-CHILD-V2" + struct.pack(">II", spi_in, spi_out)
    km = hkdf_expand(prk, info, 64)
    return km[:32], km[32:]


class SimSa:
    def __init__(self, init_spi: int, resp_spi: int, policy_flags: int, kem_alg: int) -> None:
        self.init_spi = init_spi
        self.resp_spi = resp_spi
        self.policy_flags = policy_flags
        self.kem_alg = kem_alg
        self.completed_rounds = 0
        self.peer_id = 0
        self.established = False
        self.deleted = False
        self.nonce_i = b""
        self.nonce_r = b""
        self.init_req_hash = b""
        self.init_resp_hash = b""
        self.int_auth_i = b"\x00" * 32
        self.int_auth_r = b"\x00" * 32
        self.keys: dict[str, bytes] = {}
        self.peer_msg_id = 1
        self.local_msg_id = 0
        self.child: dict[str, object] | None = None
        self.pending_local: dict[str, object] | None = None
        self.collision_peer: dict[str, object] | None = None


class TraceBuilder:
    """Builds binary KEX1 traces and tracks exact reference digests for compliant runs."""

    def __init__(self, seed: int, server_id: int = 0x53525631, psk: bytes = b"KEX-BENCHMARK-PSK-SECRET-KEY-001") -> None:
        self.seed = seed
        self.server_id = server_id
        self.psk = psk
        self.drbg = Drbg(seed)
        self.peer_rng = Drbg(seed ^ 0xA5A55A5A)
        self.steps: list[tuple[int, int, bytes]] = []
        self.tx_hash = hashlib.sha256()
        self.probe_acc = b"\x00" * 32
        self.probe_count = 0
        self.probe_lines: list[str] = []
        self.sas: list[SimSa] = []

    def _record_tx(self, pkt: bytes) -> None:
        self.tx_hash.update(struct.pack(">I", len(pkt)) + pkt)

    def add_raw_pkt(self, pkt: bytes) -> None:
        self.steps.append((KEX_TRACE_OP_RECV_PKT, 0, pkt))

    def add_raw_probe(self, sa: SimSa, seq_no: int, data: bytes) -> None:
        body = struct.pack(">QQI", sa.init_spi, sa.resp_spi, seq_no) + data
        self.steps.append((KEX_TRACE_OP_DATA_PROBE, 0, body))

    def step_sa_init(self, init_spi: int, policy_flags: int, kem_alg: int, peer_cspi: int) -> SimSa:
        peer_priv, peer_pub = dh_keypair_from_drbg(self.peer_rng)
        nonce_i = self.peer_rng.generate(32)
        req_body = pack_proposal(KEX_DH_MODP256, policy_flags, peer_cspi, kem_alg) + pack_ke(peer_pub) + pack_nonce(nonce_i)
        req = pack_header(init_spi, 0, KEX_EXCH_SA_INIT, KEX_FLAG_INITIATOR, KEX_UNIT_SA_PROPOSAL, 0, KEX_HDR_LEN + len(req_body)) + req_body
        self.add_raw_pkt(req)

        resp_spi = int.from_bytes(self.drbg.generate(8), "big") or 0x0102030405060708
        srv_priv, srv_pub = dh_keypair_from_drbg(self.drbg)
        nonce_r = self.drbg.generate(32)
        local_cspi = int.from_bytes(self.drbg.generate(4), "big") or 0x01000001

        sa = SimSa(init_spi, resp_spi, policy_flags, kem_alg)
        sa.nonce_i = nonce_i
        sa.nonce_r = nonce_r
        dh_ss = dh_shared(srv_priv, peer_pub)
        assert dh_ss == dh_shared(peer_priv, srv_pub)
        sa.keys = derive_ike_keys(nonce_i, nonce_r, dh_ss, init_spi, resp_spi)
        sa.child = {"spi_in": local_cspi, "spi_out": peer_cspi}

        resp_body = pack_proposal(KEX_DH_MODP256, policy_flags, local_cspi, kem_alg) + pack_ke(srv_pub) + pack_nonce(nonce_r)
        resp = pack_header(init_spi, resp_spi, KEX_EXCH_SA_INIT, KEX_FLAG_RESPONSE, KEX_UNIT_SA_PROPOSAL, 0, KEX_HDR_LEN + len(resp_body)) + resp_body
        self._record_tx(resp)
        sa.init_req_hash = sha256(req)
        sa.init_resp_hash = sha256(resp)
        self.sas.append(sa)
        return sa

    def _send_encrypted_or_frags(self, sa: SimSa, exch_type: int, flags: int, msg_id: int, inner_first: int, plain: bytes, frag_plan: list[tuple[int, int, bytes]] | None = None) -> None:
        if frag_plan is None:
            iv = self.peer_rng.generate(8)
            pkt = wrap_sk_packet(sa.init_spi, sa.resp_spi, exch_type, flags, msg_id, inner_first, plain, sa.keys["sk_ei"], sa.keys["sk_ai"], iv)
            self.add_raw_pkt(pkt)
        else:
            for fnum, ftotal, chunk in frag_plan:
                iv = self.peer_rng.generate(8)
                pkt = wrap_skf_packet(sa.init_spi, sa.resp_spi, exch_type, flags, msg_id, fnum, ftotal, inner_first, chunk, sa.keys["sk_ei"], sa.keys["sk_ai"], iv)
                self.add_raw_pkt(pkt)

    def step_intermediate(self, sa: SimSa, round_num: int, ctx_bytes: bytes = b"", frag_order: list[int] | None = None) -> None:
        _, peer_pk = kem_keypair(self.peer_rng.generate(32), round_num)
        plain = pack_kem(round_num, sa.kem_alg, peer_pk)
        if ctx_bytes:
            plain += pack_notify(KEX_NOTIFY_INTERMEDIATE_CTX, KEX_PROTO_IKE, 0, ctx_bytes)

        msg_id = sa.peer_msg_id
        frag_plan = None
        if frag_order is not None:
            total = max(frag_order)
            step_sz = max(1, (len(plain) + total - 1) // total)
            chunks = [plain[i * step_sz : (i + 1) * step_sz] for i in range(total)]
            frag_plan = [(idx, total, chunks[idx - 1]) for idx in frag_order]

        self._send_encrypted_or_frags(sa, KEX_EXCH_INTERMEDIATE, KEX_FLAG_INITIATOR, msg_id, KEX_UNIT_KEM_DATA, plain, frag_plan)

        ct, pq_ss = kem_encaps_sim(self.drbg, round_num, peer_pk)
        rplain = pack_kem(round_num, sa.kem_alg, ct)
        srv_iv = self.drbg.generate(8)
        resp = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_INTERMEDIATE, KEX_FLAG_RESPONSE, msg_id, KEX_UNIT_KEM_DATA, rplain, sa.keys["sk_er"], sa.keys["sk_ar"], srv_iv)
        self._record_tx(resp)

        sa.int_auth_i = update_int_auth(sa.int_auth_i, sa.init_spi, sa.resp_spi, KEX_EXCH_INTERMEDIATE, KEX_FLAG_INITIATOR, msg_id, plain)
        sa.int_auth_r = update_int_auth(sa.int_auth_r, sa.init_spi, sa.resp_spi, KEX_EXCH_INTERMEDIATE, KEX_FLAG_RESPONSE, msg_id, rplain)
        sa.keys = reseed_ike_keys(sa.keys["sk_d"], round_num, pq_ss, sa.nonce_i, sa.nonce_r, sa.init_spi, sa.resp_spi)
        sa.completed_rounds += 1
        sa.peer_msg_id += 1

    def step_auth(
        self,
        sa: SimSa,
        peer_id: int = 0x434C4E54,
        frag_order: list[int] | None = None,
        override_int_i: bytes | None = None,
        override_int_r: bytes | None = None,
        override_rounds: int | None = None,
    ) -> None:
        use_rounds = sa.completed_rounds if override_rounds is None else override_rounds
        use_i = sa.int_auth_i if override_int_i is None else override_int_i
        use_r = sa.int_auth_r if override_int_r is None else override_int_r

        mac_i = compute_auth_mac(sa.keys["sk_pi"], self.psk, sa.init_req_hash, sa.nonce_r, peer_id, use_i, use_r, use_rounds)
        assert sa.child is not None
        peer_cspi = int(sa.child["spi_out"])
        local_cspi = int(sa.child["spi_in"])
        plain = pack_id(peer_id) + pack_auth(mac_i) + pack_proposal(0, sa.policy_flags, peer_cspi, sa.kem_alg)

        msg_id = sa.peer_msg_id
        frag_plan = None
        if frag_order is not None:
            total = max(frag_order)
            step_sz = max(1, (len(plain) + total - 1) // total)
            chunks = [plain[i * step_sz : (i + 1) * step_sz] for i in range(total)]
            frag_plan = [(idx, total, chunks[idx - 1]) for idx in frag_order]

        self._send_encrypted_or_frags(sa, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, msg_id, KEX_UNIT_ID, plain, frag_plan)

        sk_ci, sk_cr = derive_child_keys(sa.keys["sk_d"], sa.nonce_i, sa.nonce_r, local_cspi, peer_cspi)
        sa.child = {"spi_in": local_cspi, "spi_out": peer_cspi, "sk_i": sk_ci, "sk_r": sk_cr}

        mac_r = compute_auth_mac(sa.keys["sk_pr"], self.psk, sa.init_resp_hash, sa.nonce_i, self.server_id, sa.int_auth_i, sa.int_auth_r, sa.completed_rounds)
        rplain = pack_id(self.server_id) + pack_auth(mac_r) + pack_proposal(0, sa.policy_flags, local_cspi, sa.kem_alg)
        srv_iv = self.drbg.generate(8)
        resp = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_RESPONSE, msg_id, KEX_UNIT_ID, rplain, sa.keys["sk_er"], sa.keys["sk_ar"], srv_iv)
        self._record_tx(resp)

        sa.peer_id = peer_id
        sa.peer_msg_id += 1
        sa.established = True

    def step_local_rekey_init(self, sa: SimSa, override_spi: int, override_nonce: bytes, use_pfs: bool = False) -> None:
        assert sa.child is not None
        old_spi_in = int(sa.child["spi_in"])
        spi_in = override_spi if override_spi != 0 else (int.from_bytes(self.drbg.generate(4), "big") or 0x01000001)
        nonce_i = override_nonce if any(override_nonce) else self.drbg.generate(32)
        pfs_priv, pfs_pub = (dh_keypair_from_drbg(self.drbg) if use_pfs else (b"", b""))

        plain = pack_notify(KEX_NOTIFY_REKEY_SA, KEX_PROTO_CHILD, old_spi_in)
        plain += pack_proposal(KEX_DH_MODP256 if use_pfs else 0, sa.policy_flags, spi_in, 0)
        plain += pack_nonce(nonce_i)
        if use_pfs:
            plain += pack_ke(pfs_pub)

        msg_id = sa.local_msg_id
        sa.local_msg_id += 1
        srv_iv = self.drbg.generate(8)
        out_pkt = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_CREATE_CHILD, 0, msg_id, KEX_UNIT_NOTIFY, plain, sa.keys["sk_er"], sa.keys["sk_ar"], srv_iv)
        self._record_tx(out_pkt)

        sa.pending_local = {"msg_id": msg_id, "spi_in": spi_in, "nonce_i": nonce_i, "use_pfs": use_pfs, "pfs_priv": pfs_priv}
        body = struct.pack(">QQI", sa.init_spi, sa.resp_spi, override_spi) + override_nonce
        self.steps.append((KEX_TRACE_OP_LOCAL_REKEY_INIT, 1 if use_pfs else 0, body))

    def step_peer_rekey_req(self, sa: SimSa, peer_new_spi: int, peer_nonce: bytes, use_pfs: bool = False) -> None:
        assert sa.child is not None
        target_spi = int(sa.child["spi_out"])
        peer_priv, peer_pub = (dh_keypair_from_drbg(self.peer_rng) if use_pfs else (b"", b""))
        plain = pack_notify(KEX_NOTIFY_REKEY_SA, KEX_PROTO_CHILD, target_spi)
        plain += pack_proposal(KEX_DH_MODP256 if use_pfs else 0, sa.policy_flags, peer_new_spi, 0)
        plain += pack_nonce(peer_nonce)
        if use_pfs:
            plain += pack_ke(peer_pub)

        msg_id = sa.peer_msg_id
        self._send_encrypted_or_frags(sa, KEX_EXCH_CREATE_CHILD, KEX_FLAG_INITIATOR, msg_id, KEX_UNIT_NOTIFY, plain)

        pfs_ss = None
        srv_pub = b""
        if use_pfs:
            srv_priv, srv_pub = dh_keypair_from_drbg(self.drbg)
            pfs_ss = dh_shared(srv_priv, peer_pub)
            assert pfs_ss == dh_shared(peer_priv, srv_pub)

        local_spi = int.from_bytes(self.drbg.generate(4), "big") or 0x01000001
        nonce_r = self.drbg.generate(32)
        sk_ci, sk_cr = derive_child_keys(sa.keys["sk_d"], peer_nonce, nonce_r, local_spi, peer_new_spi, pfs_ss)
        cand = {
            "spi_in": local_spi,
            "spi_out": peer_new_spi,
            "nonce_i": peer_nonce,
            "nonce_r": nonce_r,
            "min_nonce": min(peer_nonce, nonce_r),
            "sk_i": sk_ci,
            "sk_r": sk_cr,
        }

        rplain = pack_proposal(KEX_DH_MODP256 if use_pfs else 0, sa.policy_flags, local_spi, 0) + pack_nonce(nonce_r)
        if use_pfs:
            rplain += pack_ke(srv_pub)
        srv_iv = self.drbg.generate(8)
        resp = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_CREATE_CHILD, KEX_FLAG_RESPONSE, msg_id, KEX_UNIT_SA_PROPOSAL, rplain, sa.keys["sk_er"], sa.keys["sk_ar"], srv_iv)
        self._record_tx(resp)

        sa.peer_msg_id += 1
        if sa.pending_local is not None:
            sa.collision_peer = cand
        else:
            sa.child = cand

    def step_peer_rekey_resp(self, sa: SimSa, peer_spi_out: int, peer_nonce_r: bytes, reject_notify: int = 0) -> None:
        assert sa.pending_local is not None
        pend = sa.pending_local
        sa.pending_local = None
        msg_id = int(pend["msg_id"])
        use_pfs = bool(pend["use_pfs"])

        if reject_notify != 0:
            plain = pack_notify(reject_notify, KEX_PROTO_CHILD, 0)
            self._send_encrypted_or_frags(sa, KEX_EXCH_CREATE_CHILD, KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE, msg_id, KEX_UNIT_NOTIFY, plain)
            if sa.collision_peer is not None:
                sa.child = sa.collision_peer
                sa.collision_peer = None
            return

        pfs_ss = None
        plain = pack_proposal(KEX_DH_MODP256 if use_pfs else 0, sa.policy_flags, peer_spi_out, 0) + pack_nonce(peer_nonce_r)
        if use_pfs:
            _, peer_pub = dh_keypair_from_drbg(self.peer_rng)
            plain += pack_ke(peer_pub)
            pfs_ss = dh_shared(bytes(pend["pfs_priv"]), peer_pub)

        self._send_encrypted_or_frags(sa, KEX_EXCH_CREATE_CHILD, KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE, msg_id, KEX_UNIT_SA_PROPOSAL, plain)

        spi_in = int(pend["spi_in"])
        nonce_i = bytes(pend["nonce_i"])
        sk_ci, sk_cr = derive_child_keys(sa.keys["sk_d"], nonce_i, peer_nonce_r, spi_in, peer_spi_out, pfs_ss)
        local_cand = {
            "spi_in": spi_in,
            "spi_out": peer_spi_out,
            "nonce_i": nonce_i,
            "nonce_r": peer_nonce_r,
            "min_nonce": min(nonce_i, peer_nonce_r),
            "sk_i": sk_ci,
            "sk_r": sk_cr,
        }

        if sa.collision_peer is not None:
            peer_cand = sa.collision_peer
            sa.collision_peer = None
            if bytes(local_cand["min_nonce"]) >= bytes(peer_cand["min_nonce"]):
                sa.child = local_cand
            else:
                sa.child = peer_cand
        else:
            sa.child = local_cand

    def step_delete(self, sa: SimSa, proto_id: int) -> None:
        spi = int(sa.child["spi_out"]) if (proto_id == KEX_PROTO_CHILD and sa.child) else 0
        plain = pack_delete(proto_id, spi, 1 if proto_id == KEX_PROTO_CHILD else 0)
        msg_id = sa.peer_msg_id
        self._send_encrypted_or_frags(sa, KEX_EXCH_INFORMATIONAL, KEX_FLAG_INITIATOR, msg_id, KEX_UNIT_DELETE, plain)

        rplain = b""
        inner_first = 0
        if proto_id == KEX_PROTO_CHILD and sa.child is not None:
            rplain = pack_delete(KEX_PROTO_CHILD, int(sa.child["spi_in"]), 1)
            inner_first = KEX_UNIT_DELETE
            sa.child = None
        srv_iv = self.drbg.generate(8)
        resp = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_INFORMATIONAL, KEX_FLAG_RESPONSE, msg_id, inner_first, rplain, sa.keys["sk_er"], sa.keys["sk_ar"], srv_iv)
        self._record_tx(resp)
        sa.peer_msg_id += 1
        if proto_id == KEX_PROTO_IKE:
            sa.established = False
            sa.deleted = True

    def step_probe(self, sa: SimSa, seq_no: int, data: bytes) -> None:
        body = struct.pack(">QQI", sa.init_spi, sa.resp_spi, seq_no) + data
        self.steps.append((KEX_TRACE_OP_DATA_PROBE, 0, body))

        assert sa.child is not None
        spi_in = int(sa.child["spi_in"])
        spi_out = int(sa.child["spi_out"])
        hdr_meta = struct.pack(">III", spi_in, spi_out, seq_no)
        dir_i = hmac_sha256(bytes(sa.child["sk_i"]), hdr_meta + data)
        tag = hmac_sha256(bytes(sa.child["sk_r"]), dir_i + hdr_meta)
        self.probe_acc = sha256(self.probe_acc + hdr_meta + tag)
        self.probe_count += 1
        self.probe_lines.append(f"PROBE seq={seq_no} spi_in={spi_in:08x} spi_out={spi_out:08x} tag={tag[:8].hex()}")

    def serialize(self) -> bytes:
        hdr = struct.pack(">IIIII", KEX_TRACE_MAGIC, self.seed, self.server_id, len(self.steps), 0) + self.psk
        chunks = [hdr]
        for op, flags, body in self.steps:
            chunks.append(struct.pack(">BBHI", op, flags, 0, len(body)) + body)
        return b"".join(chunks)

    def expected_summary(self) -> str:
        tx_hex = self.tx_hash.copy().digest()[:8].hex()
        sh = hashlib.sha256()
        sh.update(self.probe_acc)
        active = 0
        for sa in self.sas:
            if not sa.established or sa.deleted:
                continue
            active += 1
            sh.update(struct.pack(">QQHHI", sa.init_spi, sa.resp_spi, sa.policy_flags, sa.completed_rounds, sa.peer_id))
            sh.update(sa.keys["sk_d"])
            if sa.child is not None:
                sh.update(struct.pack(">II", int(sa.child["spi_in"]), int(sa.child["spi_out"])))
                sh.update(bytes(sa.child["sk_i"]))
                sh.update(bytes(sa.child["sk_r"]))
        st_hex = sh.digest()[:8].hex()
        return f"OK steps={len(self.steps)} active_sas={active} probes={self.probe_count} tx_digest={tx_hex} state_digest={st_hex}"


def build_functional_cases() -> list[tuple[str, bytes, list[str], str]]:
    cases: list[tuple[str, bytes, list[str], str]] = []

    # 1. Classic non-hybrid handshakes + Child/IKE SA deletion
    tb1 = TraceBuilder(0x20260101)
    sa1 = tb1.step_sa_init(0x1111222233334444, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0xA1000001)
    tb1.step_auth(sa1, peer_id=0x1001)
    tb1.step_probe(sa1, 1, b"classic-channel-frame-alpha")
    tb1.step_delete(sa1, KEX_PROTO_CHILD)
    tb1.step_delete(sa1, KEX_PROTO_IKE)
    sa2 = tb1.step_sa_init(0x5555666677778888, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0xA1000002)
    tb1.step_auth(sa2, peer_id=0x1002)
    tb1.step_probe(sa2, 2, b"classic-channel-frame-beta")
    cases.append(("classic_handshake_and_delete", tb1.serialize(), tb1.probe_lines, tb1.expected_summary()))

    # 2. Mandatory 1-round hybrid handshake with IntAuth context binding
    tb2 = TraceBuilder(0x20260202)
    sa_h1 = tb2.step_sa_init(0x9999AAAABBBBCCCC, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0xB2000001)
    tb2.step_intermediate(sa_h1, 1, ctx_bytes=b"pq-hybrid-context-v1")
    tb2.step_auth(sa_h1, peer_id=0x2001)
    tb2.step_probe(sa_h1, 10, b"hybrid-1round-verified-stream")
    cases.append(("hybrid_1round_intauth", tb2.serialize(), tb2.probe_lines, tb2.expected_summary()))

    # 3. Mandatory 2-round hybrid handshake with out-of-order + idempotent duplicate encrypted fragments
    tb3 = TraceBuilder(0x20260303)
    sa_h2 = tb3.step_sa_init(0xDDDDEEEEFFFF0001, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_HYBRID_DUAL, 0xC3000001)
    tb3.step_intermediate(sa_h2, 1, ctx_bytes=b"dual-round-r1")
    tb3.step_intermediate(sa_h2, 2, ctx_bytes=b"dual-round-r2-fragmented", frag_order=[2, 1])
    tb3.step_auth(sa_h2, peer_id=0x3001, frag_order=[3, 1, 3, 2])
    tb3.step_probe(sa_h2, 20, b"hybrid-2round-ooo-reassembled")
    cases.append(("hybrid_2round_fragmented_ooo", tb3.serialize(), tb3.probe_lines, tb3.expected_summary()))

    # 4. Normal PFS rekey + simultaneous rekey where local_cand wins tie-breaker
    tb4 = TraceBuilder(0x20260404)
    sa_rw = tb4.step_sa_init(0x123456789ABCDEF0, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0xD4000001)
    tb4.step_intermediate(sa_rw, 1)
    tb4.step_auth(sa_rw, peer_id=0x4001)
    tb4.step_probe(sa_rw, 30, b"pre-rekey-traffic")
    tb4.step_peer_rekey_req(sa_rw, 0xD4000002, b"\x55" * 32, use_pfs=True)
    tb4.step_probe(sa_rw, 31, b"post-pfs-rekey-traffic")
    # Simultaneous rekey: local min_nonce = 0xE0.. > peer min_nonce = 0x20.. -> local_cand wins
    tb4.step_local_rekey_init(sa_rw, 0xE4000010, b"\xE0" * 32, use_pfs=True)
    tb4.step_peer_rekey_req(sa_rw, 0xD4000003, b"\x20" * 32, use_pfs=False)
    tb4.step_peer_rekey_resp(sa_rw, 0xD4000004, b"\xF0" * 32)
    tb4.step_probe(sa_rw, 32, b"post-simul-win-traffic")
    cases.append(("rekey_pfs_and_simul_winner", tb4.serialize(), tb4.probe_lines, tb4.expected_summary()))

    # 5. Simultaneous rekey where local_cand LOSES tie-breaker + TEMP_FAILURE rollback & collision promotion
    tb5 = TraceBuilder(0x20260505)
    sa_rl = tb5.step_sa_init(0x0FEDCBA987654321, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0xE5000001)
    tb5.step_intermediate(sa_rl, 1, ctx_bytes=b"rekey-loser-flow")
    tb5.step_auth(sa_rl, peer_id=0x5001)
    tb5.step_probe(sa_rl, 40, b"initial-sa-traffic")
    # Simultaneous rekey: local_cand nonce_i = 0x05.. -> min_local = 0x05..; peer_cand nonce_i = 0xFE.. (and srv nonce_r > 0x05..) -> peer_cand wins!
    tb5.step_local_rekey_init(sa_rl, 0xF5000011, b"\x05" * 32, use_pfs=False)
    tb5.step_peer_rekey_req(sa_rl, 0xE5000002, b"\xFE" * 32, use_pfs=False)
    tb5.step_peer_rekey_resp(sa_rl, 0xE5000003, b"\x90" * 32)
    tb5.step_probe(sa_rl, 41, b"after-loser-rollback-must-use-peer-cand")
    # Non-colliding local rekey rejected with TEMP_FAILURE -> must keep active peer_cand
    tb5.step_local_rekey_init(sa_rl, 0xF5000012, b"\x33" * 32, use_pfs=False)
    tb5.step_peer_rekey_resp(sa_rl, 0, b"", reject_notify=KEX_NOTIFY_TEMP_FAILURE)
    tb5.step_probe(sa_rl, 42, b"after-temp-failure-keep-active")
    # Colliding local rekey rejected with TEMP_FAILURE -> must promote newly accepted collision_peer
    tb5.step_local_rekey_init(sa_rl, 0xF5000013, b"\x44" * 32, use_pfs=False)
    tb5.step_peer_rekey_req(sa_rl, 0xE5000009, b"\x77" * 32, use_pfs=True)
    tb5.step_peer_rekey_resp(sa_rl, 0, b"", reject_notify=KEX_NOTIFY_TEMP_FAILURE)
    tb5.step_probe(sa_rl, 43, b"after-collision-temp-failure-promoted")
    cases.append(("rekey_simul_loser_and_temp_failure", tb5.serialize(), tb5.probe_lines, tb5.expected_summary()))

    return cases


def build_adversarial_cases() -> list[tuple[str, bytes]]:
    adv: list[tuple[str, bytes]] = []

    # A1: Skip mandatory 1-round KEX_INTERMEDIATE directly from SA_INIT to AUTH
    t = TraceBuilder(0x3001)
    sa = t.step_sa_init(0xA001000000000001, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0x7001)
    t.step_auth(sa, peer_id=0x6001, override_rounds=0)
    t.step_probe(sa, 1, b"should-not-establish")
    adv.append(("skip_mandatory_hybrid_1round", t.serialize()))

    # A2: Complete only round 1 of 2-round HYBRID_DUAL then jump to KEX_AUTH
    t = TraceBuilder(0x3002)
    sa = t.step_sa_init(0xA002000000000002, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_HYBRID_DUAL, 0x7002)
    t.step_intermediate(sa, 1)
    t.step_auth(sa, peer_id=0x6002)
    t.step_probe(sa, 1, b"should-reject-partial-hybrid")
    adv.append(("skip_round2_of_dual_hybrid", t.serialize()))

    # A3: Complete KEX_INTERMEDIATE but omit IntAuth from KEX_AUTH MAC (rounds=0)
    t = TraceBuilder(0x3003)
    sa = t.step_sa_init(0xA003000000000003, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0x7003)
    t.step_intermediate(sa, 1, ctx_bytes=b"authentic-ctx")
    t.step_auth(sa, peer_id=0x6003, override_rounds=0)
    adv.append(("omitted_intauth_in_auth", t.serialize()))

    # A4: Tampered initiator intermediate transcript hash in AUTH
    t = TraceBuilder(0x3004)
    sa = t.step_sa_init(0xA004000000000004, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0x7004)
    t.step_intermediate(sa, 1, ctx_bytes=b"orig-notify-bytes")
    bad_int_i = bytes([sa.int_auth_i[0] ^ 0xFF]) + sa.int_auth_i[1:]
    t.step_auth(sa, peer_id=0x6004, override_int_i=bad_int_i)
    adv.append(("tampered_intauth_req", t.serialize()))

    # A5: Tampered responder intermediate transcript hash in AUTH
    t = TraceBuilder(0x3005)
    sa = t.step_sa_init(0xA005000000000005, KEX_POLICY_HYBRID_REQUIRED, KEX_KEM_MLKEM768, 0x7005)
    t.step_intermediate(sa, 1)
    bad_int_r = bytes([sa.int_auth_r[0] ^ 0x55]) + sa.int_auth_r[1:]
    t.step_auth(sa, peer_id=0x6005, override_int_r=bad_int_r)
    adv.append(("tampered_intauth_resp", t.serialize()))

    # B1: Malformed CREATE_CHILD response (missing nonce) must rollback without UAF/double-unref at teardown
    t = TraceBuilder(0x3006)
    sa = t.step_sa_init(0xB006000000000006, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x7006)
    t.step_auth(sa, peer_id=0x6006)
    t.step_local_rekey_init(sa, 0x80060001, b"\x42" * 32, use_pfs=False)
    bad_resp_plain = pack_proposal(0, sa.policy_flags, 0x90060001, 0)
    bad_resp = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_CREATE_CHILD, KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE, 0, KEX_UNIT_SA_PROPOSAL, bad_resp_plain, sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x11" * 8)
    t.add_raw_pkt(bad_resp)
    adv.append(("rekey_malformed_resp_rollback", t.serialize()))

    # B2: Invalid PFS DH public value (pub=1) in CREATE_CHILD response during collision must rollback cleanly
    t = TraceBuilder(0x3007)
    sa = t.step_sa_init(0xB007000000000007, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x7007)
    t.step_auth(sa, peer_id=0x6007)
    t.step_local_rekey_init(sa, 0x80070001, b"\x12" * 32, use_pfs=True)
    t.step_peer_rekey_req(sa, 0x90070001, b"\xEE" * 32, use_pfs=False)
    bad_pfs_plain = pack_proposal(KEX_DH_MODP256, sa.policy_flags, 0x90070002, 0) + pack_nonce(b"\x34" * 32) + pack_ke((1).to_bytes(32, "big"))
    bad_pfs_pkt = wrap_sk_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_CREATE_CHILD, KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE, 0, KEX_UNIT_SA_PROPOSAL, bad_pfs_plain, sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x22" * 8)
    t.add_raw_pkt(bad_pfs_pkt)
    adv.append(("rekey_bad_pfs_pub_collision_rollback", t.serialize()))

    # C1: Encrypted fragment with frag_num = 0
    t = TraceBuilder(0x3008)
    sa = t.step_sa_init(0xC008000000000008, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x7008)
    f0 = wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 0, 2, KEX_UNIT_ID, b"badfrag0", sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x31" * 8)
    t.add_raw_pkt(f0)
    adv.append(("frag_zero_index", t.serialize()))

    # C2: Encrypted fragment with frag_num > total_frags (1/2 then 3/2)
    t = TraceBuilder(0x3009)
    sa = t.step_sa_init(0xC009000000000009, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x7009)
    mac_i = compute_auth_mac(sa.keys["sk_pi"], t.psk, sa.init_req_hash, sa.nonce_r, 0x6009, None, None, 0)
    auth_plain = pack_id(0x6009) + pack_auth(mac_i) + pack_proposal(0, sa.policy_flags, 0x7009, 0)
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 1, 2, KEX_UNIT_ID, auth_plain, sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x41" * 8))
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 3, 2, KEX_UNIT_ID, b"", sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x42" * 8))
    t.add_raw_probe(sa, 1, b"must-not-complete")
    adv.append(("frag_num_exceeds_total", t.serialize()))

    # C3: Mutated total_frags growing mid-reassembly (1/2 then 3/4, 2/4, 4/4) -> heap OOB on slots[2..3]
    t = TraceBuilder(0x300A)
    sa = t.step_sa_init(0xC00A00000000000A, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x700A)
    mac_i = compute_auth_mac(sa.keys["sk_pi"], t.psk, sa.init_req_hash, sa.nonce_r, 0x600A, None, None, 0)
    auth_plain = pack_id(0x600A) + pack_auth(mac_i) + pack_proposal(0, sa.policy_flags, 0x700A, 0)
    q = len(auth_plain) // 4
    parts = [auth_plain[:q], auth_plain[q : 2 * q], auth_plain[2 * q : 3 * q], auth_plain[3 * q :]]
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 1, 2, KEX_UNIT_ID, parts[0], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x51" * 8))
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 3, 4, KEX_UNIT_ID, parts[2], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x52" * 8))
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 2, 4, KEX_UNIT_ID, parts[1], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x53" * 8))
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 4, 4, KEX_UNIT_ID, parts[3], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x54" * 8))
    t.add_raw_probe(sa, 1, b"must-reject-grown-total-frags")
    adv.append(("frag_total_grow_oob", t.serialize()))

    # C4: Mutated total_frags shrinking mid-reassembly (1/4 then 2/2) -> premature reassembly
    t = TraceBuilder(0x300B)
    sa = t.step_sa_init(0xC00B00000000000B, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x700B)
    mac_i = compute_auth_mac(sa.keys["sk_pi"], t.psk, sa.init_req_hash, sa.nonce_r, 0x600B, None, None, 0)
    auth_plain = pack_id(0x600B) + pack_auth(mac_i) + pack_proposal(0, sa.policy_flags, 0x700B, 0)
    mid = len(auth_plain) // 2
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 1, 4, KEX_UNIT_ID, auth_plain[:mid], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x61" * 8))
    t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 2, 2, KEX_UNIT_ID, auth_plain[mid:], sa.keys["sk_ei"], sa.keys["sk_ai"], b"\x62" * 8))
    t.add_raw_probe(sa, 1, b"must-reject-shrunk-total-frags")
    adv.append(("frag_total_shrink_premature", t.serialize()))

    # C5: Duplicate fragment 1/3 sent 3 times without 2/3 or 3/3
    t = TraceBuilder(0x300C)
    sa = t.step_sa_init(0xC00C00000000000C, KEX_POLICY_CLASSIC_ONLY, KEX_KEM_NONE, 0x700C)
    mac_i = compute_auth_mac(sa.keys["sk_pi"], t.psk, sa.init_req_hash, sa.nonce_r, 0x600C, None, None, 0)
    auth_plain = pack_id(0x600C) + pack_auth(mac_i) + pack_proposal(0, sa.policy_flags, 0x700C, 0)
    for iv_b in (0x71, 0x72, 0x73):
        t.add_raw_pkt(wrap_skf_packet(sa.init_spi, sa.resp_spi, KEX_EXCH_AUTH, KEX_FLAG_INITIATOR, 1, 1, 3, KEX_UNIT_ID, auth_plain, sa.keys["sk_ei"], sa.keys["sk_ai"], bytes([iv_b]) * 8))
    t.add_raw_probe(sa, 1, b"duplicate-frags-must-stay-pending")
    adv.append(("frag_duplicate_completion", t.serialize()))

    return adv


def supports_asan() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        c_file = Path(tmp) / "probe.c"
        bin_file = Path(tmp) / "probe"
        c_file.write_text("int main(void){return 0;}\n", encoding="utf-8")
        res = subprocess.run(
            ["gcc", "-fsanitize=address,undefined", str(c_file), "-o", str(bin_file)],
            capture_output=True,
        )
        return res.returncode == 0


def compile_sanitized(app_dir: Path, out_bin: Path, use_asan: bool) -> None:
    src_dir = app_dir / "src"
    srcs = [
        src_dir / "sha256_hkdf.c",
        src_dir / "packet.c",
        src_dir / "frag.c",
        src_dir / "sa_table.c",
        src_dir / "rekey.c",
        src_dir / "state_machine.c",
        src_dir / "cli.c",
    ]
    cmd = ["gcc", "-std=c11", "-Wall", "-Wextra", "-O1", "-g", "-fno-omit-frame-pointer", f"-I{app_dir / 'include'}"]
    if use_asan:
        cmd.append("-fsanitize=address,undefined")
    cmd += [str(s) for s in srcs] + ["-o", str(out_bin)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{res.stderr}")


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_cli(bin_path: Path, trace_file: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:exitcode=99:abort_on_error=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=98"
    env["MALLOC_PERTURB_"] = "165"
    return subprocess.run(
        [str(bin_path), str(trace_file)],
        capture_output=True,
        text=True,
        env=env,
        preexec_fn=_disable_core_dumps,
        timeout=15,
    )


def did_crash(proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode < 0 or proc.returncode in (98, 99) or proc.returncode >= 128:
        return True
    err = proc.stderr
    if "AddressSanitizer" in err or " runtime error:" in err or "Segmentation fault" in err or "Aborted" in err:
        return True
    return False


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"
    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_files = data.get("files")
    findings = data.get("findings")
    summary = str(data.get("summary", "")).strip()

    if not isinstance(raw_files, list) or not raw_files:
        return False, "report.json 'files' must be a non-empty list"
    if not isinstance(findings, list) or len(findings) < 2:
        return False, "report.json 'findings' must be a list of findings"
    if len(summary) < 20:
        return False, "report.json 'summary' is empty or too brief"

    blob = json.dumps({"files": raw_files, "findings": findings})
    mentioned = {Path(tok).name for tok in re.findall(r"[\w./-]+\.[ch]\b", blob)}
    matched = mentioned & TARGET_FILES
    if len(matched) < 2:
        return False, f"report.json does not reference expected engine modules (found {sorted(mentioned)})"
    return True, f"Report covers modules: {sorted(matched)}"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    del tests_dir
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    make_res = subprocess.run(["make", "-C", str(app_dir), "all"], capture_output=True, text=True)
    app_bin = app_dir / "build" / "kex_cli"
    if make_res.returncode != 0 or not app_bin.is_file():
        results["build"] = {"passed": False, "message": make_res.stderr.strip() or "Missing /app/build/kex_cli"}
        return False, results

    use_asan = supports_asan()
    results["asan_enabled"] = use_asan

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        san_bin = tmp / "san_kex_cli"
        try:
            compile_sanitized(app_dir, san_bin, use_asan=use_asan)
        except RuntimeError as exc:
            results["build"] = {"passed": False, "message": str(exc)}
            return False, results
        results["build"] = {"passed": True}

        # 1. Functional suite on both /app/build/kex_cli and sanitized rebuild
        for label, blob, exp_probes, exp_summary in build_functional_cases():
            f_in = tmp / f"func_{label}.bin"
            f_in.write_bytes(blob)
            for bname, bpath in (("app_bin", app_bin), ("san_bin", san_bin)):
                proc = run_cli(bpath, f_in)
                lines = [ln.strip() for ln in proc.stdout.strip().splitlines() if ln.strip()]
                exp_lines = [*exp_probes, exp_summary]
                if did_crash(proc) or proc.returncode != 0 or lines != exp_lines:
                    results["functional"] = {
                        "passed": False,
                        "case": label,
                        "binary": bname,
                        "rc": proc.returncode,
                        "expected": exp_lines,
                        "got": lines,
                        "stderr": proc.stderr.strip()[:400],
                    }
                    return False, results
        results["functional"] = {"passed": True, "message": "All classic, hybrid, fragmented, and simultaneous-rekey flows matched reference digests"}

        # 2. Adversarial suite
        for label, blob in build_adversarial_cases():
            f_adv = tmp / f"adv_{label}.bin"
            f_adv.write_bytes(blob)
            proc = run_cli(san_bin, f_adv)
            if did_crash(proc) or proc.returncode != 1 or "\nOK " in ("\n" + proc.stdout):
                results["adversarial"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc.returncode,
                    "crashed": did_crash(proc),
                    "stdout": proc.stdout.strip(),
                    "stderr": proc.stderr.strip()[:400],
                }
                return False, results
        results["adversarial"] = {"passed": True, "message": "All 12 protocol-skip, transcript-tamper, rekey-rollback, and fragment-mutation cases cleanly rejected"}

    return True, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    tests_dir = Path(__file__).resolve().parent
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, tests_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
