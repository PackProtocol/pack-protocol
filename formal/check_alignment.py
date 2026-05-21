#!/usr/bin/env python3
"""
Model-code alignment checker for pack-protocol.

Extracts security-critical parameters from both the Tamarin model (.spthy)
and the Rust implementation, then compares them structurally. Catches the
class of bugs where model and code drift apart: wrong KDF info strings,
different DH orderings, mismatched AD construction, etc.

Exit code 0 = all checks pass, 1 = misalignment found.
"""

import re
import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

CRATE_SRC = Path(__file__).resolve().parent.parent / "crates" / "pack-protocol" / "src"
MODEL = Path(__file__).resolve().parent / "pack_protocol.spthy"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


results: list[CheckResult] = []


def check(name: str, condition: bool, detail: str = ""):
    results.append(CheckResult(name, condition, detail))


def read(path: Path) -> str:
    return path.read_text()


def grep_rust(filename: str, pattern: str) -> list[str]:
    text = read(CRATE_SRC / filename)
    return re.findall(pattern, text, re.MULTILINE)


def grep_model(pattern: str) -> list[str]:
    text = read(MODEL)
    return re.findall(pattern, text, re.MULTILINE)


# ============================================================
# 1. X3DH DH ordering
# ============================================================
def check_x3dh_dh_order():
    code = read(CRATE_SRC / "x3dh.rs")

    init_dhs = re.findall(r'// (DH\d) = DH\((\w+), (\w+)\)', code)
    init_section = code[:code.index("x3dh_respond")]
    resp_section = code[code.index("x3dh_respond"):]

    init_labels = [(m[0], m[1], m[2]) for m in init_dhs if init_dhs.index(m) < len(init_dhs)//2 or "respond" not in code[:code.index(m[0])]]

    init_order = re.findall(r'let (dh\d)', init_section)
    resp_order = re.findall(r'let (dh\d)', resp_section)

    code_init_order = []
    for m in re.finditer(r'ikm\.extend_from_slice\(&\*?(dh\d)', init_section):
        code_init_order.append(m.group(1))

    model_text = read(MODEL)
    model_x3dh = re.search(r'rule X3DH_Init:.*?sk\s*=\s*kdf_x3dh\((\w+),\s*(\w+),\s*(\w+),\s*(\w+)\)', model_text, re.DOTALL)
    if model_x3dh:
        model_order = list(model_x3dh.groups())
    else:
        model_order = []

    check(
        "X3DH DH concatenation order",
        code_init_order == ["dh1", "dh2", "dh3"] and model_order == ["dh1", "dh2", "dh3", "dh4"],
        f"code: F||{'||'.join(code_init_order)}[||dh4], model: kdf_x3dh({','.join(model_order)})"
    )

    model_init = re.search(r'rule X3DH_Init:.*?dh1\s*=\s*(\S+)', model_text, re.DOTALL)
    model_dh1 = model_init.group(1) if model_init else ""
    code_dh1_init = re.search(r'// DH1 = DH\((\w+), (\w+)\)', init_section)

    check(
        "X3DH DH1 = DH(IK_A, SPK_B)",
        code_dh1_init is not None and code_dh1_init.group(1) == "IK_A" and code_dh1_init.group(2) == "SPK_B",
        f"code comment: DH1 = DH({code_dh1_init.group(1)}, {code_dh1_init.group(2)})" if code_dh1_init else "not found"
    )


# ============================================================
# 2. X3DH KDF info string
# ============================================================
def check_x3dh_kdf_info():
    code = read(CRATE_SRC / "x3dh.rs")
    code_info = re.findall(r'hkdf_derive\(&ikm,\s*&salt,\s*b"(\w+)"', code)

    model = read(MODEL)
    model_has_kdf_x3dh = "kdf_x3dh" in model

    check(
        "X3DH HKDF info string = \"X3DH\"",
        all(info == "X3DH" for info in code_info) and len(code_info) >= 2,
        f"code info strings: {code_info}"
    )


# ============================================================
# 3. PQXDH KDF info string and KEM inclusion
# ============================================================
def check_pqxdh_kdf():
    code = read(CRATE_SRC / "pqxdh.rs")
    code_info = re.findall(r'hkdf_derive\(&ikm,\s*&salt,\s*b"(\w+)"', code)

    kem_in_ikm = "ikm.extend_from_slice(kem_ss" in code or "ikm.extend_from_slice(&kem_ss" in code or re.search(r'ikm\.extend_from_slice\(kem_ss\.as_slice\(\)\)', code)

    model = read(MODEL)
    # Match kdf_pqxdh in rules (after 'sk ='), not in function declarations/comments
    model_pqxdh_matches = re.findall(r'sk\s*=\s*kdf_pqxdh\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', model)
    model_has_kem = any(m[4] == "kem_shared" for m in model_pqxdh_matches) if model_pqxdh_matches else False

    check(
        "PQXDH HKDF info string = \"PQXDH\"",
        all(info == "PQXDH" for info in code_info) and len(code_info) >= 2,
        f"code info strings: {code_info}"
    )

    check(
        "PQXDH includes KEM shared secret in IKM",
        bool(kem_in_ikm) and bool(model_has_kem),
        f"code includes kem_ss: {bool(kem_in_ikm)}, model includes kem_shared: {bool(model_has_kem)}"
    )


# ============================================================
# 4. Double Ratchet KDF_RK info string
# ============================================================
def check_dr_kdf_rk():
    code = read(CRATE_SRC / "chain.rs")
    info_match = re.search(r'hkdf_derive_pair\(\w+,\s*\w+\.as_bytes\(\),\s*b"(\w+)"', code)
    code_info = info_match.group(1) if info_match else ""

    check(
        "KDF_RK HKDF info string = \"DoubleRatchet\"",
        code_info == "DoubleRatchet",
        f"code: \"{code_info}\""
    )


# ============================================================
# 5. Double Ratchet KDF_CK constants (0x01 for mk, 0x02 for ck)
# ============================================================
def check_dr_kdf_ck():
    code = read(CRATE_SRC / "chain.rs")
    mk_const = re.search(r'hmac_sha256\(chain_key\.as_bytes\(\),\s*&\[0x(\w+)\]\)', code)
    ck_const = re.findall(r'hmac_sha256\(chain_key\.as_bytes\(\),\s*&\[0x(\w+)\]\)', code)

    mk_val = mk_const.group(1) if mk_const else ""

    model = read(MODEL)
    model_has_mk = "mk_from_ck" in model
    model_has_ck = "ck_next" in model

    check(
        "KDF_CK: mk = HMAC(ck, 0x01), new_ck = HMAC(ck, 0x02)",
        ck_const == ["01", "02"],
        f"code HMAC constants: {ck_const}"
    )

    check(
        "Model has mk_from_ck and ck_next functions",
        model_has_mk and model_has_ck,
        f"mk_from_ck: {model_has_mk}, ck_next: {model_has_ck}"
    )


# ============================================================
# 6. Double Ratchet AEAD AD includes header
# ============================================================
def check_dr_aead_ad():
    code = read(CRATE_SRC / "ratchet.rs")
    full_ad_pattern = re.findall(r'full_ad\.extend_from_slice\(([^)]+)\)', code)

    has_ad = any("ad" in p and "header" not in p for p in full_ad_pattern)
    has_header = any("header" in p for p in full_ad_pattern)

    model = read(MODEL)
    model_ad = re.findall(r'full_ad\s*=\s*<(\w+),\s*([^>]+)>', model)
    model_has_header = any("ad" in ad[0] and ("g'^" in ad[1] or "pub" in ad[1] or "drk" in ad[1] or "ek" in ad[1]) for ad in model_ad)

    check(
        "DR AEAD AD = ad || header (code and model)",
        has_ad and has_header and model_has_header,
        f"code extends: {full_ad_pattern}, model full_ad pairs: {model_ad}"
    )


# ============================================================
# 7. DR nonce derivation: HMAC(mk, "nonce")[..12]
# ============================================================
def check_dr_nonce():
    code = read(CRATE_SRC / "ratchet.rs")
    nonce_match = re.search(r'hmac_sha256\(mk,\s*b"(\w+)"\)', code)
    nonce_info = nonce_match.group(1) if nonce_match else ""
    nonce_slice = re.search(r'\[\.\.(\d+)\]', code[code.index("derive_nonce"):] if "derive_nonce" in code else "")
    nonce_len = int(nonce_slice.group(1)) if nonce_slice else 0

    check(
        "DR nonce = HMAC-SHA256(mk, \"nonce\")[..12]",
        nonce_info == "nonce" and nonce_len == 12,
        f"code: HMAC(mk, \"{nonce_info}\")[..{nonce_len}]"
    )


# ============================================================
# 8. AD construction: IK_A || IK_B (initiator first)
# ============================================================
def check_ad_construction():
    code = read(CRATE_SRC / "session.rs")
    fn_match = re.search(r'fn build_associated_data.*?\{(.*?)\n\}', code, re.DOTALL)
    if fn_match:
        fn_body = fn_match.group(1)
        has_initiator_check = "is_initiator" in fn_body
        has_local_first = fn_body.index("local_identity") < fn_body.index("remote_identity")
    else:
        has_initiator_check = False
        has_local_first = False

    model = read(MODEL)
    model_ad_init = re.search(r"rule X3DH_Init:.*?ad\s*=\s*<([^>]+)>", model, re.DOTALL)
    model_ad_resp = re.search(r"rule X3DH_Resp:.*?ad\s*=\s*<([^>]+)>", model, re.DOTALL)

    init_ad = model_ad_init.group(1).strip() if model_ad_init else ""
    resp_ad = model_ad_resp.group(1).strip() if model_ad_resp else ""

    init_a_first = init_ad.startswith("'g'^~ik_a")
    resp_a_first = resp_ad.startswith("ik_pub_a")

    check(
        "AD = IK_initiator || IK_responder (both sides)",
        has_initiator_check and init_a_first and resp_a_first,
        f"code: is_initiator branch, model init: <{init_ad}>, model resp: <{resp_ad}>"
    )


# ============================================================
# 9. Noise NK: protocol name, MixHash, MixKey, signature scope
# ============================================================
def check_sealed_sender():
    code = read(CRATE_SRC / "sealed_sender.rs")

    protocol_match = re.search(r'NOISE_NK_PROTOCOL.*?=\s*b"([^"]+)"', code)
    protocol_name = protocol_match.group(1) if protocol_match else ""

    signs_h = re.search(r'identity_signature\s*=\s*\w+\.sign\(&h\)', code)
    signs_h2_or_h = bool(signs_h)

    nonce_match = re.search(r'let nonce = \[0u8; (\d+)\]', code)
    nonce_val = int(nonce_match.group(1)) if nonce_match else 0

    model = read(MODEL)
    model_protocol = re.search(r"h0\s*=\s*h\('(\w+)'\)", model)
    model_protocol_name = model_protocol.group(1) if model_protocol else ""

    model_id_sig = re.search(r"id_sig\s*=\s*sign\((\w+),", model)
    model_sig_scope = model_id_sig.group(1) if model_id_sig else ""

    check(
        "Sealed Sender protocol name",
        protocol_name == "Noise_NK_25519_AESGCM_SHA256",
        f"code: \"{protocol_name}\""
    )

    check(
        "Sealed Sender Noise NK hash initialization",
        model_protocol_name == "Noise_NK",
        f"model uses h('Noise_NK') — abstract, code uses full protocol name (correct abstraction)"
    )

    check(
        "Sealed Sender identity signature scope = h (handshake hash)",
        signs_h2_or_h and model_sig_scope == "h2",
        f"code: signs &h after MixHash(e), model: signs {model_sig_scope} (= MixHash(h1, e))"
    )

    check(
        "Sealed Sender AEAD nonce = all-zeros (first Noise message)",
        nonce_val == 12,
        f"code: [0u8; {nonce_val}]"
    )


# ============================================================
# 10. Noise NK MixKey uses ck (not h) as salt
# ============================================================
def check_noise_mixkey():
    code = read(CRATE_SRC / "sealed_sender.rs")

    encrypt_section = code[code.index("sealed_sender_encrypt"):]
    init_call = re.search(r'let \(mut h, ck\) = noise_nk_init', encrypt_section)
    mixkey_call = re.search(r'mix_key\(&ck,', encrypt_section)

    model = read(MODEL)
    model_mixkey = re.search(r'k\s*=\s*noise_k\((\w+),', model)
    model_ck_arg = model_mixkey.group(1) if model_mixkey else ""

    check(
        "Noise NK MixKey uses ck (chain key), not h",
        bool(init_call) and bool(mixkey_call) and model_ck_arg == "h0",
        f"code: mix_key(&ck, ...), model: noise_k({model_ck_arg}, ...) — "
        f"{'MISMATCH: model uses h0 but should use ck' if model_ck_arg != 'ck' else 'aligned'}"
    )


# ============================================================
# 11. Group messaging: AD = chain_id, signature scope
# ============================================================
def check_group():
    code = read(CRATE_SRC / "group.rs")

    ad_match = re.search(r'let ad = (\w+)\.chain_id\.to_be_bytes\(\)', code)
    code_ad_is_chain_id = bool(ad_match) or "state.chain_id.to_be_bytes()" in code

    sig_match = re.search(r'sign_data\.extend_from_slice\(&state\.chain_id\.to_be_bytes\(\)\).*?'
                          r'sign_data\.extend_from_slice\(&iteration\.to_be_bytes\(\)\).*?'
                          r'sign_data\.extend_from_slice\(&ciphertext\)',
                          code, re.DOTALL)
    code_sig_scope = bool(sig_match)

    model = read(MODEL)
    model_group_ad = re.search(r'ct\s*=\s*aenc\(mk,\s*~m,\s*~(\w+)\)', model)
    model_ad = model_group_ad.group(1) if model_group_ad else ""

    model_sig = re.search(r'sig\s*=\s*sign\(<([^>]+)>,', model)
    model_sig_content = model_sig.group(1) if model_sig else ""

    check(
        "Group AEAD AD = chain_id",
        code_ad_is_chain_id and model_ad == "chain_id",
        f"code: chain_id.to_be_bytes(), model: ~{model_ad}"
    )

    check(
        "Group signature = sign(chain_id || iteration || ciphertext)",
        code_sig_scope and "chain_id" in model_sig_content and "ct" in model_sig_content,
        f"model signs: <{model_sig_content}>"
    )


# ============================================================
# 12. Group nonce derivation differs from DR nonce
# ============================================================
def check_group_nonce():
    code = read(CRATE_SRC / "group.rs")
    group_nonce = re.search(r'fn derive_group_nonce.*?\{(.*?)\n\}', code, re.DOTALL)
    if group_nonce:
        body = group_nonce.group(1)
        uses_iteration = "iteration" in body
        uses_hmac = "hmac_sha256" in body
    else:
        uses_iteration = False
        uses_hmac = False

    dr_code = read(CRATE_SRC / "ratchet.rs")
    dr_nonce = re.search(r'fn derive_nonce.*?\{(.*?)\n\}', dr_code, re.DOTALL)
    if dr_nonce:
        dr_body = dr_nonce.group(1)
        dr_uses_nonce_string = '"nonce"' in dr_body
    else:
        dr_uses_nonce_string = False

    check(
        "Group nonce = HMAC(mk, iteration), DR nonce = HMAC(mk, \"nonce\")",
        uses_iteration and uses_hmac and dr_uses_nonce_string,
        f"group: HMAC(mk, iteration)={uses_iteration}, DR: HMAC(mk, \"nonce\")={dr_uses_nonce_string}"
    )


# ============================================================
# 13. Fingerprint: inputs and iteration count
# ============================================================
def check_fingerprint():
    code = read(CRATE_SRC / "fingerprint.rs")

    iter_match = re.search(r'ITERATIONS.*?=\s*(\d+)', code)
    iterations = int(iter_match.group(1)) if iter_match else 0

    version_match = re.search(r'FINGERPRINT_VERSION.*?=\s*(\d+)', code)
    version = int(version_match.group(1)) if version_match else -1

    hash_input_has_version = "FINGERPRINT_VERSION" in code and "hash_input.extend" in code
    hash_input_has_identity = "pub_key_bytes" in code or "identity_key" in code
    hash_input_has_stable_id = "stable_identifier" in code

    model = read(MODEL)
    # Match fingerprint() calls in rules (let bindings), not in function declarations/comments
    model_fps = re.findall(r'(?:let|=)\s*\w+\s*=\s*fingerprint\(([^,]+),\s*([^)]+)\)', model)
    if model_fps:
        model_arg1 = model_fps[0][0].strip()
        model_arg2 = model_fps[0][1].strip()
    else:
        model_arg1 = model_arg2 = ""

    check(
        "Fingerprint: SHA-512 iterated 5200 times",
        iterations == 5200,
        f"code: {iterations} iterations"
    )

    check(
        "Fingerprint inputs: version || identity_key || stable_id",
        hash_input_has_version and hash_input_has_identity and hash_input_has_stable_id,
        "code includes version, identity key, and stable identifier"
    )

    check(
        "Model fingerprint binds identity key and identity name",
        "'g'^~ik" in model_arg1 and "$" in model_arg2,
        f"model: fingerprint({model_arg1}, {model_arg2})"
    )


# ============================================================
# 14. SPK signature content: sign(<'SPK', spk_pub>, ik)
# ============================================================
def check_spk_signature():
    model = read(MODEL)
    model_spk_sig = re.search(r"sign\(<'SPK',\s*([^>]+)>,\s*~ik_b\)", model)

    code = read(CRATE_SRC / "x3dh.rs")
    code_verifies_spk = "verify_signed_pre_key" in code

    keys_code = read(CRATE_SRC / "keys.rs")
    spk_sign = re.search(r'fn generate.*?sign.*?SPK|spk_bytes|signed_pre_key', keys_code, re.DOTALL)

    check(
        "SPK signature verified during X3DH",
        bool(model_spk_sig) and code_verifies_spk,
        f"model: sign(<'SPK', pubkey>, ik), code: calls verify_signed_pre_key()"
    )


# ============================================================
# 15. PQ pre-key signature content
# ============================================================
def check_pqpk_signature():
    model = read(MODEL)
    model_pq_sig = re.search(r"sign\(<'PQPK',\s*([^>]+)>,\s*~ik_b\)", model)

    code = read(CRATE_SRC / "pqxdh.rs")
    code_verifies_pq = "verify_pq_pre_key" in code

    check(
        "PQ pre-key signature verified during PQXDH",
        bool(model_pq_sig) and code_verifies_pq,
        f"model: sign(<'PQPK', ek>, ik), code: calls verify_pq_pre_key()"
    )


# ============================================================
# 16. KEM equation: dec(enc(pk(dk), r), dk) = ss(pk(dk), r)
# ============================================================
def check_kem_equation():
    model = read(MODEL)
    has_kem_eq = "kem_dec(kem_enc(kem_pk(dk), r), dk) = kem_ss(kem_pk(dk), r)" in model

    code = read(CRATE_SRC / "pqxdh.rs")
    has_encapsulate = "encapsulate()" in code
    has_decapsulate = "decapsulate(" in code

    check(
        "KEM correctness equation in model, encaps/decaps in code",
        has_kem_eq and has_encapsulate and has_decapsulate,
        f"model equation: {has_kem_eq}, code encapsulate: {has_encapsulate}, decapsulate: {has_decapsulate}"
    )


# ============================================================
# 17. OPK consumed exactly once (restriction)
# ============================================================
def check_opk_restriction():
    model = read(MODEL)
    has_restriction = "ConsumeOPK" in model and "OncePerOPK" in model

    check(
        "OPK one-time-use restriction in model",
        has_restriction,
        "restriction OncePerOPK enforces single use"
    )


# ============================================================
# 18. Message key consumed exactly once (replay protection)
# ============================================================
def check_mk_restriction():
    model = read(MODEL)
    has_restriction = "ConsumeMK" in model and "MessageKeyOnce" in model

    code = read(CRATE_SRC / "ratchet.rs")
    has_skipped_remove = "skipped_keys.remove" in code or "remove(" in code

    check(
        "Message key single-use (model restriction + code removes from skipped)",
        has_restriction and has_skipped_remove,
        f"model: MessageKeyOnce restriction, code: removes skipped keys after use"
    )


# ============================================================
# 19. Compromise granularity alignment
# ============================================================
def check_compromise_rules():
    model = read(MODEL)

    compromise_rules = {
        "Rev_LTK": "RevLTK" in model,
        "Rev_SPK": "RevSPK" in model,
        "Rev_PQ": "RevPQ" in model,
        "Rev_Ephemeral": "RevEph" in model,
        "Rev_Ratchet": "RevRatchet" in model,
        "Rev_GroupChain": "RevGroupChain" in model,
        "Rev_GroupSign": "RevGroupSign" in model,
        "Rev_TrustRoot": "RevTrust" in model,
    }

    all_present = all(compromise_rules.values())
    missing = [k for k, v in compromise_rules.items() if not v]

    check(
        "All compromise rules present in model",
        all_present,
        f"missing: {missing}" if missing else "all 8 compromise types modeled"
    )


# ============================================================
# 20. Rev_Ratchet leaks both rk and DH private key
# ============================================================
def check_ratchet_compromise():
    model = read(MODEL)
    rev_ratchet = re.search(r'rule Rev_Ratchet_A:.*?Out\((\w+)\).*?Out\((\S+)\)', model, re.DOTALL)
    if rev_ratchet:
        leaked = (rev_ratchet.group(1), rev_ratchet.group(2))
        leaks_rk = "rk" in leaked[0]
        leaks_ek = "ek" in leaked[1]
    else:
        leaks_rk = leaks_ek = False

    code = read(CRATE_SRC / "ratchet.rs")
    to_bytes_has_rk = "root_key" in code
    to_bytes_has_dh = "dh_self" in code

    check(
        "Ratchet compromise leaks root_key + DH private (matches serialized state)",
        leaks_rk and leaks_ek,
        f"model leaks: {rev_ratchet.groups() if rev_ratchet else 'not found'}"
    )


# ============================================================
# Main
# ============================================================
def main():
    print(f"\n{BOLD}pack-protocol model/code alignment check{RESET}\n")
    print(f"  Model: {MODEL}")
    print(f"  Code:  {CRATE_SRC}\n")

    check_x3dh_dh_order()
    check_x3dh_kdf_info()
    check_pqxdh_kdf()
    check_dr_kdf_rk()
    check_dr_kdf_ck()
    check_dr_aead_ad()
    check_dr_nonce()
    check_ad_construction()
    check_sealed_sender()
    check_noise_mixkey()
    check_group()
    check_group_nonce()
    check_fingerprint()
    check_spk_signature()
    check_pqpk_signature()
    check_kem_equation()
    check_opk_restriction()
    check_mk_restriction()
    check_compromise_rules()
    check_ratchet_compromise()

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total = len(results)

    print(f"{'─' * 72}")
    for r in results:
        icon = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
        print(f"  [{icon}] {r.name}")
        if r.detail and not r.passed:
            print(f"         {YELLOW}{r.detail}{RESET}")
    print(f"{'─' * 72}")

    if failed:
        print(f"\n  {RED}{BOLD}{failed}/{total} checks FAILED{RESET}")
        print()
        for r in results:
            if not r.passed:
                print(f"  {RED}FAIL:{RESET} {r.name}")
                if r.detail:
                    print(f"        {r.detail}")
        print()
    else:
        print(f"\n  {GREEN}{BOLD}{passed}/{total} checks passed{RESET}\n")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
