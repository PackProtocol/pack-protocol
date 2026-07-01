# pack-protocol: Computational Security Reduction

## Overview

This document outlines a game-based computational security proof for pack-protocol.
It reduces the protocol's security to standard cryptographic hardness assumptions,
following the framework of Bellare-Rogaway (1993), Canetti-Krawczyk (2001), and
the protocol-specific analysis of Cohn-Gordon et al. (2020).

This is a proof *outline* suitable for a cryptographer to review, verify, and
formalize. Each theorem states the security claim, the reduction, and the
tightness bound.

---

## 1. Hardness Assumptions

### Assumption 1: Decisional Diffie-Hellman (DDH) in X25519

For generator g of the X25519 group, no PPT adversary A can distinguish
(g^a, g^b, g^{ab}) from (g^a, g^b, g^c) with non-negligible advantage:

    Adv^{DDH}_A(k) = |Pr[A(g^a, g^b, g^{ab}) = 1] - Pr[A(g^a, g^b, g^c) = 1]|

is negligible in the security parameter k.

We use DDH rather than CDH because the KDF application requires indistinguishability,
not just hardness of computation. For X25519 (Curve25519), DDH is believed to hold
under the standard elliptic curve assumptions.

### Assumption 2: PRF Security of HMAC-SHA256

HMAC-SHA256, when keyed, is a pseudorandom function. For any PPT adversary A:

    Adv^{PRF}_A(k) = |Pr[A^{HMAC(K, .)} = 1] - Pr[A^{f(.)} = 1]|

is negligible, where f is a truly random function.

### Assumption 3: IND-CPA Security of HKDF-SHA256

HKDF(ikm, salt, info, L) is indistinguishable from random when ikm has sufficient
min-entropy. Formally, for any PPT adversary A:

    Adv^{IND}_A(k) = |Pr[A(HKDF(ikm, ...)) = 1] - Pr[A(U_L) = 1]|

is negligible when H_\infty(ikm) >= k. This follows from the PRF security of
HMAC (extract step) and PRG security of HMAC in counter mode (expand step),
as shown by Krawczyk (2010).

### Assumption 4: IND-CCA2 Security of AES-256-GCM

AES-256-GCM provides IND-CCA2 security (with nonce uniqueness). For any PPT
adversary A making at most q queries with distinct nonces:

    Adv^{IND-CCA2}_A(k) <= q^2 / 2^{128} + Adv^{PRP}_{AES-256}(k)

### Assumption 5: EUF-CMA Security of XEdDSA

XEdDSA signatures (Ed25519 derived from X25519 keys) are existentially unforgeable
under chosen message attack:

    Adv^{EUF-CMA}_A(k)

is negligible under the DLP assumption in the Ed25519 group.

### Assumption 6: IND-CCA Security of ML-KEM-768

ML-KEM-768 (FIPS 203) is IND-CCA secure under the Module Learning With Errors
(MLWE) assumption:

    Adv^{IND-CCA}_A(k) <= Adv^{MLWE}_{n,k,q}(k) + negl(k)

This holds for both classical and quantum adversaries (post-quantum security).

---

## 2. Security Model: Multi-Stage Authenticated Key Exchange

We use the multi-stage AKE model of Fischlin and Günther (2014), extended for
the E2EE messaging setting by Cohn-Gordon et al. (2020).

### 2.1 Participants and Sessions

- N parties P_1, ..., P_N, each with long-term keypair (ik_i, IK_i = g^{ik_i}).
- Each party can run multiple sessions concurrently.
- A session pi_i^s at party P_i has state:
  - pid: intended partner identity
  - role: initiator or responder
  - stg: current stage (X3DH, DR epoch 0, DR epoch 1, ...)
  - sk_stg: session key at current stage
  - alpha: accept/reject flag

### 2.2 Adversary Queries

The adversary A interacts with sessions via oracle queries:

| Query | Effect |
|-------|--------|
| NewSession(i, j, role) | Create a new session at P_i targeting P_j |
| Send(i, s, m) | Deliver message m to session pi_i^s |
| RevealKey(i, s, stg) | Reveal the session key at stage stg |
| RevealState(i, s) | Reveal the current ratchet state |
| Corrupt(i) | Reveal long-term key ik_i |
| CorruptSPK(i) | Reveal signed pre-key spk_i |
| CorruptPQ(i) | Reveal PQ decapsulation key dk_i |
| Test(i, s, stg) | Challenge: receive either real sk or random |

### 2.3 Freshness

A session pi_i^s at stage stg is **fresh** if none of the following hold:

1. RevealKey(i, s, stg) was queried.
2. RevealKey(j, s', stg) was queried for the matching session pi_j^{s'}.
3. RevealState(i, s) was queried AND no subsequent DH ratchet step occurred.
4. Corrupt(i) AND Corrupt(j) were both queried.
5. Corrupt(j) AND CorruptSPK(j) were both queried before session acceptance
   (for X3DH-only; PQXDH relaxes this — see Theorem 3).

### 2.4 Advantage

The adversary's advantage against the AKE security game is:

    Adv^{AKE}_A = |Pr[A wins] - 1/2|

where A wins if it correctly guesses the Test bit for a fresh session.

---

## 3. Theorems and Reductions

### Theorem 1: X3DH Session Key Secrecy

**Claim.** The X3DH key agreement protocol is a secure AKE in the multi-stage
model under the DDH assumption in X25519, PRF security of HMAC-SHA256, and
IND-CPA security of HKDF.

**Bound.**

    Adv^{AKE}_{X3DH}(k) <= 4 * n_s * Adv^{DDH}(k) + n_s * Adv^{PRF}_{HKDF}(k)

where n_s is the maximum number of sessions.

**Reduction sketch.**

Given an adversary A that breaks X3DH session key secrecy, we construct a
DDH distinguisher B:

1. B receives a DDH challenge (g^a, g^b, Z) where Z = g^{ab} or Z = g^c.

2. B embeds the challenge into one of the four DH computations (DH1-DH4),
   chosen uniformly at random (losing a factor of 4).

3. For the chosen DH slot, say DH2 = IK_B^{EK_A}:
   - Set IK_B = g^a (program B's identity key)
   - Set EK_A = g^b (program A's ephemeral key)
   - Then DH2 = Z

4. For the remaining DH slots, B computes honestly using known secret keys.

5. B computes SK = HKDF(DH1 || DH2 || DH3 || DH4) using Z for the embedded slot.

6. If Z = g^{ab}: SK is correctly distributed (real game).
   If Z = g^c:  DH2 is independent of the protocol → SK is independent of
   the real key (random game), by the extraction property of HKDF.

7. B simulates the rest of the protocol for A. When A outputs its Test guess,
   B outputs the same bit as its DDH guess.

**Key step.** The HKDF extraction lemma (Krawczyk, 2010) ensures that if any
one of the four DH inputs has sufficient min-entropy (which g^{ab} has under
DDH), the HKDF output is computationally indistinguishable from random.

**Tightness.** The reduction loses a factor of 4 * n_s due to:
- Factor 4: guessing which DH slot to embed the challenge in
- Factor n_s: guessing which session the adversary targets

This matches the tightness of Cohn-Gordon et al. (2020, Theorem 1).

---

### Theorem 2: X3DH Forward Secrecy

**Claim.** X3DH provides forward secrecy: compromise of long-term keys (IK_A,
IK_B) and signed pre-key (SPK_B) after session establishment does not reveal
past session keys.

**Bound.**

    Adv^{FS}_{X3DH}(k) <= 2 * n_s * Adv^{DDH}(k) + n_s * Adv^{PRF}_{HKDF}(k)

**Reduction sketch.**

After the session is established, the adversary learns ik_a, ik_b, spk_b.
This reveals DH1 = g^{spk_b * ik_a} and parts of DH3.

However, DH2 = IK_B^{EK_A} = g^{ik_b * ek_a} and DH4 = OPK_B^{EK_A} = g^{opk_b * ek_a}
still involve the ephemeral key ek_a, which was erased after session setup.

The reduction embeds a DDH challenge in DH2 or DH4 (factor of 2). The adversary
knows ik_b and ik_a (from Corrupt queries after the session), but not ek_a.
The DDH challenge in the (g^{ik_b}, g^{ek_a}, Z) triple remains hard.

**Why SPK compromise after the session is safe.** DH1 = g^{spk_b * ik_a} becomes
known, and DH3 = g^{spk_b * ek_a} — the adversary knows spk_b but not ek_a.
Embed the DDH challenge as (g^{spk_b}, g^{ek_a}, Z) for DH3, or use DH2/DH4.
One of DH2, DH3, DH4 remains hard because ek_a is ephemeral and erased.

---

### Theorem 3: PQXDH Hybrid Security

**Claim.** PQXDH session keys are secure if *either* DDH holds in X25519 *or*
IND-CCA holds for ML-KEM-768. The adversary must break both to recover the
session key.

**Bound.**

    Adv^{AKE}_{PQXDH}(k) <= min(
        4 * n_s * Adv^{DDH}(k) + n_s * Adv^{PRF}_{HKDF}(k),
        n_s * Adv^{IND-CCA}_{ML-KEM}(k) + n_s * Adv^{PRF}_{HKDF}(k)
    )

**Reduction sketch.**

PQXDH computes SK = HKDF(DH1 || DH2 || DH3 || DH4 || KEM_SS).

**Case 1: DDH holds (classical security).**
Even if the adversary has a quantum computer that breaks ML-KEM (i.e., they
know KEM_SS), the four DH slots are still protected by DDH. The reduction
from Theorem 1 applies unchanged — embed a DDH challenge in one DH slot.
The adversary knowing KEM_SS just means one of the five HKDF inputs is known,
but the remaining DDH-protected input provides sufficient min-entropy for
HKDF extraction.

**Case 2: ML-KEM holds (post-quantum security).**
Even if the adversary breaks DDH (i.e., they know all four DH values), KEM_SS
is protected by IND-CCA security of ML-KEM-768.

Reduce to IND-CCA: given a KEM challenge (ek*, ct*, K_0, K_1) where K_b is
either the real shared secret or random:
- Embed ek* as Bob's PQ public key
- Embed ct* as Alice's KEM ciphertext
- Use K_b as KEM_SS in the HKDF computation
- If K_b is real, SK is correctly distributed
- If K_b is random, SK is independent (HKDF extraction)

**Key insight.** HKDF's extraction property ensures that if *any one* of the
five inputs has sufficient min-entropy, the output is pseudorandom. Since at
least one of {DH1..DH4, KEM_SS} is computationally hard (by assumption), SK
is indistinguishable from random.

---

### Theorem 4: Double Ratchet Message Secrecy

**Claim.** Messages encrypted under the Double Ratchet are IND-CCA2 secure,
given that the session key is secure (Theorem 1/3), HMAC-SHA256 is a PRF,
HKDF is a secure KDF, and AES-256-GCM is IND-CCA2.

**Bound.**

    Adv^{MSG}_{DR}(k) <= Adv^{AKE}(k) + n_e * Adv^{DDH}(k)
                        + n_m * Adv^{PRF}_{HMAC}(k)
                        + n_m * Adv^{IND-CCA2}_{AES-GCM}(k)

where n_e is the number of DH ratchet epochs, n_m is the number of messages.

**Reduction sketch.**

The Double Ratchet derives message keys through a two-level KDF chain:

```
Level 1 (DH ratchet):  (RK', CK) = HKDF(RK, g^{ab})
Level 2 (symmetric):    MK = HMAC(CK, 0x01),  CK' = HMAC(CK, 0x02)
```

**Step 1: Replace SK with random.**
By Theorem 1 or 3, the initial root key (X3DH session key) is indistinguishable
from random. Cost: Adv^{AKE}(k).

**Step 2: Hybrid over DH ratchet epochs.**
For each DH ratchet step, the new DH output g^{ab} (where a and b are fresh
ephemeral keys) is indistinguishable from random under DDH. Replace each DH
output with a random value. By HKDF extraction, the resulting (RK', CK) pair
is indistinguishable from random.

Apply this epoch-by-epoch in a hybrid argument over n_e epochs.
Cost: n_e * Adv^{DDH}(k) + n_e * Adv^{PRF}_{HKDF}(k).

**Step 3: Hybrid over chain keys.**
Within each epoch, the chain key advances via CK' = HMAC(CK, 0x02). By PRF
security of HMAC, each CK' is indistinguishable from random given that CK is
random (which we established in Step 2). Apply inductively over the chain.

Cost: n_m * Adv^{PRF}_{HMAC}(k).

**Step 4: Replace message keys with random.**
MK = HMAC(CK, 0x01). By PRF security (CK is random from Step 3), MK is
indistinguishable from random.

**Step 5: Invoke IND-CCA2 of AES-256-GCM.**
With random message keys, ciphertext indistinguishability follows directly
from IND-CCA2 of AES-256-GCM.

Cost: n_m * Adv^{IND-CCA2}_{AES-GCM}(k).

---

### Theorem 5: Break-in Recovery

**Claim.** If the adversary compromises the ratchet state (root key + current
DH private key) at epoch t, messages sent after the next DH ratchet step
(epoch t+2, requiring one round-trip) are secret, provided the new DH keys
are uncompromised.

**Bound.**

    Adv^{BIR}_{DR}(k) <= Adv^{DDH}(k) + Adv^{PRF}_{HKDF}(k)
                        + Adv^{PRF}_{HMAC}(k) + Adv^{IND-CCA2}_{AES-GCM}(k)

**Reduction sketch.**

At compromise, the adversary learns RK_t and dh_priv_t. The peer generates
fresh dh_priv_{t+1}. The DH ratchet step computes:

    (RK_{t+1}, CK_{t+1}) = HKDF(RK_t, g^{dh_priv_t * dh_priv_{t+1}})

The adversary knows RK_t and dh_priv_t but NOT dh_priv_{t+1}. The DH output
g^{dh_priv_t * dh_priv_{t+1}} is a fresh DDH instance — embed the DDH
challenge as (g^{dh_priv_t}, g^{dh_priv_{t+1}}, Z).

If Z = g^{dh_priv_t * dh_priv_{t+1}}: real game.
If Z = g^c: HKDF input has fresh entropy → RK_{t+1} and CK_{t+1} are
indistinguishable from random → message keys are random → IND-CCA2.

**Why one round-trip is required.** The compromised party's next message
uses CK derived from the compromised RK_t. Only after the peer replies
(contributing fresh DH entropy via dh_priv_{t+1}) does the ratchet heal.
This matches the exists-trace property verified in the Tamarin model.

---

### Theorem 6: Sealed Sender Anonymity

**Claim.** The Noise NK-based sealed sender envelope provides sender anonymity
against the server (network adversary), under DDH in X25519 and IND-CCA2 of
AES-256-GCM.

**Bound.**

    Adv^{ANON}_{SS}(k) <= n_s * Adv^{DDH}(k) + n_s * Adv^{IND-CCA2}_{AES-GCM}(k)

**Reduction sketch.**

The Noise NK handshake computes:
```
h = Hash("Noise_NK")
h = MixHash(h, recipient_pub)
e = fresh ephemeral
h = MixHash(h, e_pub)
k = MixKey(h, DH(e, recipient_static))
ct = AEAD(k, sender_identity || cert || inner_msg, ad=h)
```

The server sees (e_pub, ct) but not the sender identity.

**Step 1.** DH(e, recipient_static) = recipient_pub^e_priv. Under DDH, this
is indistinguishable from random (the server does not know recipient_priv).

**Step 2.** With a random DH output, k = MixKey(h, random) is pseudorandom.

**Step 3.** With a random k, the AEAD ciphertext is IND-CCA2 — the server
cannot distinguish between ciphertexts from different senders.

**Note.** Anonymity requires that the recipient's long-term key is not
compromised. If the server colludes with the recipient (who reveals their
private key), anonymity is trivially broken — this matches the model's
exclusion of RevLTK(R) in the ss_anonymity lemma.

---

### Theorem 7: Group Sender Authentication

**Claim.** Group messages are authenticated: a received message with a valid
signature was produced by the claimed sender, under EUF-CMA of XEdDSA.

**Bound.**

    Adv^{AUTH}_{GRP}(k) <= n_g * Adv^{EUF-CMA}_{XEdDSA}(k)

where n_g is the number of group senders.

**Reduction sketch.**

Each sender key distribution includes pk(sign_sk). The receiver verifies
`verify(sig, (gid, iteration, ct), pk(sign_sk))` before accepting.

Given a forger A that produces a valid (ct*, sig*) for sender S without
compromising S's signing key, construct an EUF-CMA forger B:

1. B receives a verification key vk* from the EUF-CMA challenger.
2. B programs vk* as the signing verification key for sender S.
3. When A produces a forgery (ct*, sig*) accepted under vk*, B outputs
   (msg = (gid, iteration, ct*), sig*) as its EUF-CMA forgery.

---

### Theorem 8: Group Chain Forward Secrecy

**Claim.** Compromise of a group chain key at iteration t does not reveal
messages from iterations 0, ..., t-1, under PRF security of HMAC-SHA256.

**Bound.**

    Adv^{FS}_{GRP}(k) <= t * Adv^{PRF}_{HMAC}(k) + t * Adv^{IND-CCA2}_{AES-GCM}(k)

**Reduction sketch.**

The chain advances via CK_{i+1} = HMAC(CK_i, 0x02), and message keys are
derived as MK_i = HMAC(CK_i, 0x01).

**Forward direction only.** Given CK_t, the adversary can compute CK_{t+1},
CK_{t+2}, ... (chain is one-way forward). But computing CK_{t-1} from CK_t
requires inverting HMAC, which contradicts PRF security.

**Hybrid argument.** Replace CK_0 with random (by chain key secrecy). Then
replace MK_0 with random (PRF). Then replace CK_1 = HMAC(CK_0, 0x02) with
random (PRF, since CK_0 is random). Continue inductively through iteration t.

At iteration t, CK_t is random (from the hybrid), but the adversary receives
the *real* CK_t via compromise. This creates a distinguishing event, ending
the hybrid. Messages at iterations 0..t-1 use independent random MK values
in the hybrid, so their ciphertexts are IND-CCA2.

**Limitation.** Groups lack a DH ratchet, so there is no break-in recovery.
Compromise of CK_t reveals all *future* messages (t+1, t+2, ...) until the
sender re-keys. This is an inherent limitation of the Sender Keys design.

---

### Theorem 9: Deniability

**Claim.** The protocol provides offline deniability: given the transcript and
the session key, either party can produce a simulated transcript
indistinguishable from a real one.

**Argument (information-theoretic, not computational).**

X3DH produces a shared secret SK known to both Alice and Bob. All subsequent
messages are encrypted with AEAD under keys derived from SK via symmetric
KDFs (HMAC, HKDF). No asymmetric signatures are applied to message content.

Given SK, any party can:
1. Derive the same chain of root keys, chain keys, and message keys.
2. Encrypt arbitrary plaintexts under those message keys.
3. Produce valid AEAD ciphertexts indistinguishable from real ones.

Therefore, a transcript {ct_1, ct_2, ...} could have been produced by either
party. No third-party verifier can determine which party authored which message,
because both parties have equal capability to forge.

**Formal statement.** There exists a PPT simulator Sim such that for any
transcript T produced by an honest execution between A and B:

    {Sim(SK, role_A)} ≈_c {T}

where ≈_c denotes computational indistinguishability (in fact, the distributions
are identical given SK, making this information-theoretic).

**Limitation.** This is *offline* deniability (the judge does not interact with
the parties during protocol execution). *Online* deniability (where the judge
participates in real-time) is a stronger property that X3DH does not provide,
as noted by Vatandas et al. (2020).

**Note on group messages.** Group messages ARE signed (XEdDSA on each ciphertext),
so group messaging does NOT provide deniability. A group message with a valid
signature under sender S's key constitutes a non-repudiable proof of authorship.
This is an intentional design tradeoff: group authentication is prioritized over
deniability.

---

## 4. Summary of Reductions

| Theorem | Property | Reduces to | Tightness loss |
|---------|----------|------------|----------------|
| 1 | X3DH secrecy | DDH + HKDF-PRF | 4 * n_s |
| 2 | X3DH forward secrecy | DDH + HKDF-PRF | 2 * n_s |
| 3 | PQXDH hybrid security | min(DDH, ML-KEM IND-CCA) + HKDF-PRF | 4 * n_s |
| 4 | DR message secrecy | DDH + HMAC-PRF + AES-GCM IND-CCA2 | n_e + n_m |
| 5 | Break-in recovery | DDH + HKDF-PRF + AES-GCM IND-CCA2 | O(1) |
| 6 | Sealed sender anonymity | DDH + AES-GCM IND-CCA2 | n_s |
| 7 | Group authentication | XEdDSA EUF-CMA | n_g |
| 8 | Group chain FS | HMAC-PRF + AES-GCM IND-CCA2 | t |
| 9 | Deniability | Information-theoretic (given SK) | exact |

---

## 5. Open Questions for Reviewer

1. **Tightness of Theorem 3.** The PQXDH hybrid bound uses a min over two
   reductions. Is a tighter "hybrid-hybrid" argument possible that avoids
   the factor-4 DDH loss when the KEM is assumed secure?

2. **Multi-stage composition.** Theorems 1-4 are proved independently. A
   formal composition theorem (e.g., via the multi-stage AKE framework of
   Fischlin-Günther 2014) would justify combining them. Is the Cohn-Gordon
   composition result directly applicable, or does the PQXDH extension
   require a modified composition argument?

3. **Induction over unbounded DR epochs.** Theorem 4 bounds security for
   n_e epochs and n_m messages. A formal inductive argument (or invocation
   of the generic composition theorem for ratcheted key exchange from
   Jaeger-Stepanovs 2018) would extend this to unbounded sessions.

4. **KEM binding.** The PQXDH spec binds the KEM shared secret into the
   KDF alongside the DH values. Does the binding provide collision resistance
   against an adversary who controls the KEM public key? (Relevant if the
   server is malicious and substitutes PQ pre-keys.)

5. **AES-GCM nonce uniqueness.** The security of AES-256-GCM depends on
   nonce uniqueness (catastrophic failure on nonce reuse). The implementation
   derives nonces from message keys via HMAC. A proof that nonce collisions
   occur with probability at most n_m^2 / 2^{128} (birthday bound on HMAC
   output truncated to 96 bits) would close this gap.

---

## 6. References

- Bellare, M. and Rogaway, P. (1993). Entity authentication and key distribution.
  CRYPTO 1993.

- Canetti, R. and Krawczyk, H. (2001). Analysis of key-exchange protocols and
  their use for building secure channels. EUROCRYPT 2001.

- Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., and Stebila, D. (2020).
  A formal security analysis of the Signal messaging protocol. Journal of
  Cryptology, 33(4):1914-1983.

- Cremers, C., Horvat, M., Hoyland, J., Scott, S., and van der Merwe, T. (2017).
  A comprehensive symbolic analysis of TLS 1.3. ACM CCS 2017.

- Fischlin, M. and Günther, F. (2014). Multi-stage key exchange and the case of
  Google's QUIC protocol. ACM CCS 2014.

- Hashimoto, K., Katsumata, S., Kwiatkowski, K., and Prest, T. (2021).
  An efficient and generic construction for Signal's handshake (X3DH):
  post-quantum, state leakage secure, and deniable. PKC 2021.

- Jaeger, J. and Stepanovs, I. (2018). Optimal channel security against
  fine-grained state compromise: the safety of messaging. CRYPTO 2018.

- Krawczyk, H. (2010). Cryptographic extraction and key derivation: the HKDF
  scheme. CRYPTO 2010.

- Vatandas, N., Gennaro, R., Ithurburn, B., and Krawczyk, H. (2020). On the
  cryptographic deniability of the Signal protocol. ACNS 2020.

- NIST (2024). FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
  Standard (ML-KEM).
