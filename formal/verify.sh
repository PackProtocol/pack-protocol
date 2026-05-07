#!/bin/bash
# Formal verification of pack-protocol using Tamarin Prover
#
# Install:
#   Ubuntu/Debian: sudo apt install tamarin-prover
#   macOS:         brew install tamarin-prover
#   From source:   https://tamarin-prover.com/manual/master/book/002_installation.html
#
# Usage:
#   ./verify.sh              # prove all lemmas (batch mode)
#   ./verify.sh interactive  # launch GUI at localhost:3001
#   ./verify.sh lemma NAME   # prove a single lemma

set -euo pipefail
cd "$(dirname "$0")"

MODEL="pack_protocol.spthy"

if ! command -v tamarin-prover &>/dev/null; then
    echo "ERROR: tamarin-prover not found"
    echo ""
    echo "Install:"
    echo "  Ubuntu/Debian: sudo apt install tamarin-prover"
    echo "  macOS:         brew install tamarin-prover"
    echo "  From source:   https://tamarin-prover.com/manual/master/book/002_installation.html"
    exit 1
fi

case "${1:-prove}" in
    interactive)
        echo "Starting Tamarin interactive mode..."
        echo "Open http://localhost:3001 in your browser"
        tamarin-prover interactive "$MODEL"
        ;;
    lemma)
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 lemma LEMMA_NAME"
            echo ""
            echo "Available lemmas:"
            grep '^lemma ' "$MODEL" | sed 's/lemma \([^:]*\):.*/  \1/'
            exit 1
        fi
        echo "Proving lemma: $2"
        tamarin-prover --prove="$2" "$MODEL"
        ;;
    prove)
        echo "Proving all lemmas in $MODEL..."
        echo ""
        tamarin-prover --prove "$MODEL"
        ;;
    *)
        echo "Usage: $0 [prove|interactive|lemma NAME]"
        exit 1
        ;;
esac
