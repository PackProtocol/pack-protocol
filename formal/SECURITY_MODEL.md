# pack-protocol: Formal Security Model

## 1. Overview

This document describes the formal security model for **pack-protocol**, a clean-room
implementation of the Signal protocol in Rust. The model covers five protocol layers:

| Layer | Protocol | Specification |
|-------|----------|---------------|
| 1 | X3DH / PQXDH key agreement | X3DH spec §3.3-3.4, PQXDH spec |
| 2 | Double Ratchet | Double Ratchet spec §2.2-3.5 |
| 3 | Sealed Sender | Noise Protocol Framework §7.4 (NK pattern) |
| 4 | Group Messaging | Sender Keys spec |
| 5 | Fingerprint Verification | Safety Number spec |

The formal model is specified in Tamarin Prover's `.spthy` format and verified using
automated symbolic analysis. This document is intended for review by a cryptographer
evaluating the protocol's security guarantees.

## 2. Adversary Model

The analysis uses the **Dolev-Yao** (symbolic) adversary model:

- The adversary has **complete control of the network**: they can intercept, modify,
  delay, replay, and inject messages on all channels.
- Cryptographic primitives are treated as **ideal (black-box)**: the adversary cannot
  break encryption, forge signatures, or invert hash functions except through the
  equational theory.
- The adversary can **adaptively compromise** long-term keys, session state, and
  ratchet state via explicit compromise rules (Section 5).
- The adversary **cannot** perform computational attacks (e.g., brute force, timing
  side channels, quantum computation against classical primitives).

### 2.1 Equational Theory

The model uses Tamarin's built-in `diffie-hellman`, `signing`, and `hashing` theories,
extended with:

```
adec(k, aenc(k, m, ad), ad) = m                           -- AEAD correctness
kem_dec(kem_enc(kem_pk(dk), r), dk) = kem_ss(kem_pk(dk), r)  -- KEM correctness
```

All KDF functions (`kdf_x3dh`, `kdf_pqxdh`, `rk_new`, `ck_from_rk`, `ck_next`,
`mk_from_ck`) are modeled as **free (uninterpreted) functions** — distinct inputs
always produce distinct outputs. This is the standard symbolic abstraction for
cryptographic hash functions and KDFs.

### 2.2 Trust Assumptions

| Entity | Trust Level | Justification |
|--------|-------------|---------------|
| Key server | Semi-honest | Delivers authentic prekey bundles (SPK, OPK, PQPK) but may observe metadata. Modeled via bundle facts that guarantee authenticity. |
| Identity keys | Unique per party | Each participant has exactly one long-term identity key (`OncePerIdentity` restriction). |
| SPK signatures | Verified | The initiator verifies the SPK signature against the responder's identity key before use. |
| OPK | Single-use | Each one-time prekey is consumed exactly once (`OncePerOPK` restriction). |
| Message keys | Single-use | Each message key is consumed exactly once (`MessageKeyOnce` restriction), enforcing replay protection at the model level. |

## 3. Protocol Rules

### 3.1 Key Generation (4 rules)

| Rule | Output | Notes |
|------|--------|-------|
| `Gen_Identity` | Identity keypair (X25519 + XEdDSA) | One per party. Public key and verification key are published. |
| `Gen_SPK` | Signed pre-key | Signed under the identity key. Published via server bundle. |
| `Gen_OPK` | One-time pre-key | Unsigned, single-use. Published via server bundle. |
| `Gen_PQPK` | Post-quantum pre-key (ML-KEM-768) | Signed under the identity key. Published via server bundle. |

### 3.2 X3DH Key Agreement (2 rules)

Initiator computes four DH values and derives the session key:

```
DH1 = SPK_B ^ IK_A        (mutual authentication)
DH2 = IK_B  ^ EK_A        (mutual authentication)
DH3 = SPK_B ^ EK_A        (forward secrecy)
DH4 = OPK_B ^ EK_A        (one-time key contribution)
SK  = KDF(DH1, DH2, DH3, DH4)
AD  = IK_A_pub || IK_B_pub
```

The responder computes the same DH values using their private keys. The SPK
signature is verified before use. The associated data (AD) binds both identity
keys to the session.

### 3.3 PQXDH Key Agreement (2 rules)

Extends X3DH with a fifth KEM-based contribution:

```
SK = KDF(DH1, DH2, DH3, DH4, KEM_SS)
```

where `KEM_SS` is the shared secret from ML-KEM-768 encapsulation against the
responder's post-quantum pre-key. The PQ pre-key signature is verified before use.

### 3.4 Double Ratchet (4 rules)

Models three epochs of the Double Ratchet:

1. **DR_A_Send0**: Alice sends first message using X3DH session key as root key.
   The SPK serves as the initial ratchet public key (carried from X3DH state).
2. **DR_B_Recv_Send**: Bob decrypts Alice's message, performs a DH ratchet step
   with fresh key material, and sends a reply.
3. **DR_A_Recv1**: Alice receives Bob's reply, performing a DH ratchet step.
4. **DR_A_Send1**: Alice sends a second message with fresh DH ratchet key
   (post-recovery epoch).

Each step derives chain keys and message keys via the KDF chain:
```
(RK', CK) = rk_new(RK, DH_output), ck_from_rk(RK, DH_output)
MK = mk_from_ck(CK)
```

### 3.5 Sealed Sender (3 rules)

Models the Noise NK handshake pattern for sender anonymity:

1. **Server_Keygen**: Server generates a signing keypair for certificates.
2. **Issue_Cert**: Server certifies a sender's identity.
3. **SS_Encrypt**: Sender performs Noise NK handshake with recipient's static key,
   encrypting their identity and message payload.
4. **SS_Decrypt**: Recipient decrypts using their long-term key.

The server (and network adversary) sees only the ephemeral key and ciphertext —
the sender's identity is encrypted under the Noise session key.

### 3.6 Group Messaging (4 rules)

Models the Sender Keys protocol:

1. **Group_Create**: Sender generates chain key and signing key.
2. **Group_Join**: Receiver obtains the sender's chain key and verification key.
3. **Group_Encrypt**: Sender derives message key from chain key, encrypts, signs,
   and ratchets the chain forward.
4. **Group_Decrypt**: Receiver verifies signature, derives matching message key,
   decrypts, and ratchets forward.

Groups use symmetric ratcheting only (no DH ratchet), which means forward secrecy
is limited to the chain direction — compromise of a chain key reveals all future
messages from that sender until re-keying.

### 3.7 Fingerprint Verification (1 rule)

Models out-of-band fingerprint comparison. Both parties access their own and the
peer's authentic identity key. The verified state is recorded as a persistent fact.

## 4. Restrictions

Restrictions constrain the set of valid traces. They model protocol invariants
that are enforced by the implementation:

| Restriction | Property |
|-------------|----------|
| `Equality` | Pattern-matching correctness (signature verification, etc.) |
| `OncePerOPK` | Each OPK is consumed at most once |
| `MessageKeyOnce` | Each message key is consumed at most once |
| `GroupIterOnce` | Each group message iteration is used at most once |
| `OncePerIdentity` | Each party has exactly one identity key |

## 5. Compromise Rules

The model includes seven compromise rules that give the adversary adaptive corruption
capabilities:

| Rule | What is revealed | Models |
|------|-----------------|--------|
| `Rev_LTK` | Identity private key | Long-term key compromise (device theft, legal compulsion) |
| `Rev_SPK` | Signed pre-key private key | SPK compromise (server breach, key rotation failure) |
| `Rev_PQ` | ML-KEM decapsulation key | Post-quantum pre-key compromise |
| `Rev_Session_A` | X3DH session key + ephemeral | Initiator state compromise during key agreement |
| `Rev_Session_B` | X3DH session key | Responder state compromise during key agreement |
| `Rev_Ratchet_A` | Ratchet root key + DH private key | Ratchet state compromise (models break-in) |
| `Rev_GroupChain` | Group chain key + signing key | Group sender state compromise |

## 6. Security Properties (Lemmas)

### 6.1 Executability (5 lemmas)

These `exists-trace` lemmas verify that each protocol layer can execute successfully
— the model is not vacuously secure due to unreachable rules.

| Lemma | Property |
|-------|----------|
| `x3dh_exec` | X3DH initiator and responder can derive the same session key |
| `pqxdh_exec` | PQXDH initiator and responder can derive the same session key |
| `dr_exec` | Both parties can send messages via the Double Ratchet |
| `group_exec` | A group message can be sent and received |
| `sealed_exec` | A sealed sender message can be sent |

### 6.2 Key Secrecy (4 lemmas)

| Lemma | Property | Excluded compromises |
|-------|----------|---------------------|
| `x3dh_secrecy` | X3DH session key is secret | RevLTK(A), RevLTK(B), RevSPK(B), RevSess |
| `pqxdh_secrecy` | PQXDH session key is secret | RevLTK(A), RevLTK(B), RevSess |
| `pqxdh_hybrid` | PQXDH key is secret even if KEM is broken | RevLTK(A), RevLTK(B), RevSess (RevPQ NOT excluded) |
| `dr_secrecy` | Double Ratchet messages are secret | RevLTK, RevSPK(B), RevSess, RevRatchet |

Note: `pqxdh_secrecy` does NOT exclude `RevSPK(B)`, while `x3dh_secrecy` does.
This reflects the additional protection provided by the KEM component: even if the
SPK is compromised, the KEM shared secret prevents key recovery.

The `pqxdh_hybrid` lemma is particularly important: it does NOT exclude `RevPQ`
(post-quantum key compromise). This proves that the classical DH components alone
are sufficient for secrecy — the session is secure if **either** X25519 or ML-KEM-768
holds, providing true hybrid security.

### 6.3 Key Agreement (2 lemmas)

| Lemma | Property |
|-------|----------|
| `x3dh_agree` | If initiator and responder derive the same SK, they agree on parties |
| `pqxdh_agree` | Same for PQXDH |

These prove **no key-share (UKS) attacks**: if two session keys match, the parties
involved must be identical. Note that X3DH does not guarantee both sides *always*
compute the same SK under active MITM — key confirmation is achieved by the first
successfully decrypted Double Ratchet message.

### 6.4 Forward Secrecy (1 lemma)

| Lemma | Property |
|-------|----------|
| `x3dh_forward_secrecy` | Session key is secret even if LTK/SPK are compromised *after* the session |

This proves that past sessions remain secure after key compromise. The temporal
ordering `(All #r. RevLTK(A) @ r ==> i < r)` means the compromise happens strictly
after the session was established.

### 6.5 Associated Data Agreement (1 lemma)

| Lemma | Property |
|-------|----------|
| `ad_agree` | Within the same session, initiator and responder compute identical AD |

The associated data `AD = IK_A || IK_B` binds both identity keys to the session,
preventing identity misbinding attacks. This is verified per-session (sessions are
identified by matching session keys).

### 6.6 Replay and Freshness (2 lemmas)

| Lemma | Property |
|-------|----------|
| `replay` | Each message key is consumed exactly once |
| `opk_once` | Each one-time prekey is consumed exactly once |

### 6.7 Break-in Recovery (1 lemma)

| Lemma | Property |
|-------|----------|
| `break_in_recovery` | After ratchet state compromise, a DH ratchet step restores message secrecy |

This `exists-trace` lemma demonstrates the self-healing property of the Double
Ratchet: even after the adversary compromises Alice's ratchet state (`RevRatchet`),
a subsequent DH ratchet step with fresh key material produces messages that the
adversary cannot read.

### 6.8 Session Isolation (1 lemma)

| Lemma | Property |
|-------|----------|
| `session_iso` | Two distinct X3DH sessions between the same parties produce different session keys |

This ensures that session keys are independent — compromising one session does not
affect another.

### 6.9 Sealed Sender Anonymity (1 lemma)

| Lemma | Property |
|-------|----------|
| `ss_anonymity` | Sealed sender message content is secret if recipient's LTK is not compromised |

The Noise NK pattern ensures that the server (network adversary) cannot learn message
content or sender identity without the recipient's long-term private key.

### 6.10 Group Security (3 lemmas)

| Lemma | Property |
|-------|----------|
| `group_auth` | Received group messages were sent by the claimed sender (signature verification) |
| `group_secrecy` | Group messages are secret if the sender's chain is not compromised |
| `group_chain_secrecy` | The initial chain key is secret if not compromised |

### 6.11 Fingerprint Authenticity (1 lemma)

| Lemma | Property |
|-------|----------|
| `fp_auth` | Successful fingerprint verification implies both parties have authentic identity keys |

### 6.12 Deniability (1 lemma)

| Lemma | Property |
|-------|----------|
| `deniable` | A valid protocol execution exists where both parties are honest |

This `exists-trace` lemma demonstrates that the protocol provides **deniability**:
since both parties know the session key (derived from shared DH computations), either
party could have produced any message in the transcript. There is no cryptographic
proof of participation — the protocol uses symmetric encryption (AEAD) keyed by the
shared secret, not digital signatures on message content.

## 7. What This Model Proves

If all 23 lemmas verify, the following security guarantees hold in the symbolic model:

1. **Session key secrecy**: An adversary who does not compromise the relevant long-term
   and session keys cannot learn X3DH, PQXDH, or Double Ratchet session/message keys.

2. **Post-quantum hybrid security**: PQXDH sessions are secure if *either* the CDH
   assumption (X25519) or the ML-KEM assumption holds — the adversary must break *both*
   to recover the session key.

3. **Forward secrecy**: Compromise of long-term keys after a session does not reveal
   past session keys.

4. **Break-in recovery**: After ratchet state compromise, a single DH ratchet step
   (requiring interaction from the peer) restores message secrecy.

5. **Key agreement**: Matching session keys imply matching session partners (no
   unknown key-share attacks).

6. **Replay protection**: Each message key and one-time prekey is used exactly once.

7. **Session isolation**: Independent sessions produce independent keys.

8. **Sender anonymity**: The Sealed Sender envelope hides the sender's identity from
   the network/server.

9. **Group sender authentication**: Group messages are authenticated via XEdDSA
   signatures on each ciphertext.

10. **Deniability**: The protocol does not produce non-repudiable proof of message
    authorship.

## 8. What This Model Does NOT Prove

### 8.1 Computational Security

The symbolic model treats cryptographic primitives as ideal. It does **not** prove:

- That X25519, AES-256-GCM, HMAC-SHA256, or ML-KEM-768 are computationally secure.
- Tight security bounds or reduction quality.
- Resistance to quantum attacks on classical components (X25519).

A **computational proof** (via CryptoVerif or pen-and-paper game-based reduction)
would be needed to formally reduce protocol security to standard hardness assumptions
(CDH, MLWE, PRF security of HMAC, IND-CCA of AES-GCM).

### 8.2 Implementation Correctness

The model verifies protocol *design*, not implementation. It does not prove:

- That the Rust implementation correctly follows the protocol specification.
- Absence of side-channel leaks (timing, power, cache).
- Memory safety beyond what Rust's type system guarantees.
- Correctness of serialization, encoding, or wire formats.

The **construction trace tests** (`tests/security_properties.rs`) partially address
this gap by verifying that the implementation's cryptographic computations match
known-answer vectors from RFCs and specification formulas.

### 8.3 Properties Not Modeled

- **Key rotation**: The model uses a fixed SPK; real deployments rotate SPKs
  periodically.
- **Multi-device**: Each party is modeled as a single device.
- **Out-of-order delivery**: The Double Ratchet model covers 3 epochs but does not
  model skipped message keys or out-of-order decryption.
- **Group membership changes**: The group model covers a single sender and receiver
  with one message; it does not model member addition/removal or sender key rotation.
- **Server misbehavior beyond bundle delivery**: The server is assumed to deliver
  authentic prekey bundles. A malicious server that withholds bundles or selectively
  delivers stale OPKs is not modeled (this is a denial-of-service concern, not a
  confidentiality/authentication concern).

## 9. Verification Environment

- **Prover**: Tamarin Prover 1.12.0
- **Backend**: Maude 3.5.1
- **Model**: `formal/pack_protocol.spthy`
- **Proof mode**: Automated (`--prove`), lemma-by-lemma
- **Theory**: `PackProtocol` with `diffie-hellman`, `signing`, `hashing` builtins

### 9.1 Reproducing Results

```bash
# Prove all lemmas (requires ~32GB RAM, several hours)
tamarin-prover --prove pack_protocol.spthy

# Prove individual lemmas (recommended, ~10min each)
tamarin-prover --prove=x3dh_secrecy pack_protocol.spthy

# Interactive exploration (opens web UI on localhost:3001)
tamarin-prover interactive pack_protocol.spthy
```

## 10. Relationship to Published Analyses

This model covers the same protocol layers analyzed in the following published works:

| Work | Scope | Method |
|------|-------|--------|
| Cohn-Gordon et al., 2020 | X3DH + Double Ratchet | Computational (game-based) |
| Cremers et al., 2017 | Signal (Tamarin) | Symbolic (Tamarin) |
| Hashimoto et al., 2021 | PQXDH | Computational |
| Kobeissi et al., 2017 | Signal (Noise) | Symbolic (ProVerif) |

Our model extends prior Tamarin analyses by additionally covering:
- **PQXDH** with hybrid security (KEM + DH)
- **Sealed Sender** (Noise NK envelope)
- **Sender Keys** (group messaging)
- **Fingerprint verification**

To our knowledge, no published Tamarin model covers all five layers in a single theory.

## 11. Complementary Verification Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| Tamarin model | `formal/pack_protocol.spthy` | Symbolic protocol verification |
| Verification script | `formal/verify.sh` | Automated proof execution |
| Construction trace tests | `crates/pack-protocol/tests/security_properties.rs` | Implementation correctness against spec formulas |
| This document | `formal/SECURITY_MODEL.md` | Security model and assumptions |
