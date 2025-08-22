# ChaCha20 + Sonobe Folding + Solidity Verifier Integration

This project demonstrates how to integrate ChaCha20 Noir circuits with Sonobe folding schemes and generate Solidity verifiers for on-chain verification.

## Quick Start

### 1. Run Basic Nova Folding Scheme

```bash
cargo run --example chacha20_performance_test
```

### 2. Enable Solidity Verifier (Optional)

If you want complete Solidity verifier functionality, install the Solidity compiler:

```bash
# Install solc
npm install -g solc

# Then uncomment Solidity-related code in chacha20_performance_test.rs
# Currently they have been activated  

```

## Performance Comparison

Performance test results based on 8 ChaCha20 proofs:

| ZK Proof System | Time (8 proofs) | Relative Performance |
|----------------|-----------------|---------------------|
| Barretenberg (Noir) | ~70.0 seconds | Baseline |
| **Noir + Sonobe Folding** | **~81.0 seconds** | **1.15x slower** |
| Gnark | ~3.0 seconds | 23.3x faster |
| Expander | ~5.0 seconds | 14.0x faster |


## Technical Architecture

```
ChaCha20 Noir Circuit
        ↓
Sonobe Nova Folding Scheme
        ↓
Decider Proof Generation
        ↓
Solidity Verifier Contract
        ↓
EVM Chain Verification
```

## Detailed Time Breakdown

- **Setup**: 63.2s (42.4%) - Nova and Decider preprocessing
- **Init**: 4.3s (2.9%) - Folding scheme initialization
- **Proving**: 23.0s (15.5%) - 8-step Nova folding
- **IVC Verification**: 138ms (0.1%) - Incremental verification
- **Decider Proving**: 58.2s (39.0%) - Final proof generation
- **Decider Verification**: 143ms (0.1%) - Final verification

**Total Time**: 149.0 seconds

