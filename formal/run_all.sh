#!/bin/bash
TAMARIN=~/Downloads/tamarin-prover-1.12.0-linux64-ubuntu/tamarin-prover
MODEL=/media/fred/Terabyte/pack-protocol/formal/pack_protocol.spthy
for lemma in x3dh_exec pqxdh_exec dr_exec group_exec sealed_exec x3dh_secrecy pqxdh_secrecy_dh_protects pqxdh_secrecy_kem_protects x3dh_agree pqxdh_agree x3dh_forward_secrecy pqxdh_forward_secrecy ad_agree dr_secrecy replay opk_once break_in_recovery break_in_recovery_all session_iso ss_anonymity ss_auth group_auth group_secrecy group_chain_secrecy fp_auth deniable; do
  echo "=== $lemma ==="
  $TAMARIN --prove=$lemma "$MODEL" 2>&1 | grep -E "$lemma.*(verified|falsified|incomplete)"
  echo ""
done
