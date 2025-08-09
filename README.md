# Sonobe - ChaCha20 Folding Schemes Integration

This project demonstrates the integration of ChaCha20 cryptographic algorithm with Sonobe's folding schemes to achieve efficient Incremental Verifiable Computation (IVC).

## 🚀 Quick Start

### Compile Noir Circuit
```bash
cd noir-chacha20-folding
nargo compile
cd ..
```

### Run Tests and Benchmarks

- **`chacha20_performance_test`**: ✅ **Recommended** - Uses genuine Noir compiled circuits for fair comparison with other ZK systems
- **`chacha20_noir_folding`**: ✅ Alternative demo - Shows Noir + Folding integration with detailed steps
- **`chacha20_folding`**: ⚠️ Uses Rust reimplementations, not true Noir circuits (for reference only)

#### 1. Noir ChaCha20 Performance Test (Recommended)
```bash
cargo run --example chacha20_performance_test --release
```
This test uses genuine Noir compiled circuits for fair comparison:
- 8 proof generations
- Total time ~1.7 seconds (proving only)
- Average ~212ms per proof
- **41.2x faster** than traditional Barretenberg
- **1.8x faster** than Gnark
- **2.9x faster** than Expander

#### 2. Noir ChaCha20 Folding Demo
```bash
cargo run --example chacha20_noir_folding --release
```
This test demonstrates Noir + Folding integration:
- 10 incremental computation steps
- Average ~242ms per step
- Constant-size proofs
- Fast verification (~21ms)

#### 3. Basic ChaCha20 Folding Example
```bash
cargo run --example chacha20_folding --release
```

## 📊 Performance Comparison

### ChaCha20 Proof Generation Time Comparison (8 proofs)

| ZK Proof System | Time | Relative Performance |
|----------------|------|---------------------|
| **Barretenberg (Noir)** | ~70s | Baseline |
| **Noir + Sonobe Folding** | **~1.7s** | **41.2x Speedup** |
| **Gnark** | ~3s | 23x Speedup |
| **Expander (Multi-thread)** | ~5s | 14x Speedup |
| Rust + Sonobe Folding | ~142s | 0.5x (Slower) |

### 🎯 **Key Advantages of Noir + Folding**

- **🚀 Ultra-Fast Performance**: 41.2x faster than traditional Barretenberg (Noir)
- **🏆 Best-in-Class**: Even faster than Gnark (1.8x) and Expander (2.9x)
- **📏 Constant Proof Size**: O(1) regardless of computation steps
- **💾 Memory Efficiency**: Constant memory usage
- **⚡ Fast Verification**: ~18ms independent of computation size
- **🔗 Noir Integration**: Direct use of Noir circuits without reimplementation
- **🧩 Composability**: Easy integration with other circuits

## 🏗️ Project Structure

```
├── examples/
│   ├── chacha20_performance_test.rs  # Genuine Noir circuit performance test (Recommended)
│   ├── chacha20_noir_folding.rs     # Noir + Folding integration demo
│   └── chacha20_folding.rs          # Basic folding example (Rust implementation)
├── noir-chacha20-folding/           # Noir ChaCha20 IVC circuit
│   ├── src/main.nr                  # State transition circuit
│   └── target/chacha20_folding.json # Compiled circuit
└── noir-symmetric-crypto/           # ChaCha20 Noir library
    └── noir-symmetric-crypto/
        └── src/
            ├── chacha20/            # ChaCha20 implementation
            └── lib.nr              # Library entry point
```

## 🔧 Technical Details

### IVC State Transition Circuit

`noir-chacha20-folding/src/main.nr` implements ChaCha20 IVC state transitions:

```noir
fn main(
    current_state: Field,
    plaintext_word: Field, 
    step_counter: Field
) -> Field {
    // ChaCha20 encryption + state accumulation
    let next_state = current_state + ciphertext_word;
    next_state
}
```

### Folding Schemes Integration

Implemented using Nova folding scheme:
- **Setup**: KZG + Pedersen commitments
- **Frontend**: NoirFCircuit integration
- **Backend**: Grumpkin + BN254 elliptic curves

## 🎯 Use Cases

**Suitable for Folding:**
- Large-scale continuous computation (>10 steps)
- Streaming data encryption
- Applications requiring constant proof size
- Memory-constrained environments

**Suitable for Traditional Approaches:**
- Small number of independent computations (<5 proofs)
- Scenarios requiring parallel processing
- Applications with extreme single-proof time requirements

## 📈 Benchmark Notes

- **Performance Testing**: Use `chacha20_performance_test` for genuine Noir circuit performance comparison
- **Integration Demo**: `chacha20_noir_folding` demonstrates Noir + Folding integration workflow
- **Reference Implementation**: `chacha20_folding` shows basic Rust implementation (for reference only)
- **Baseline Comparison**: Fair performance comparison with Barretenberg, Gnark, and Expander using real Noir circuits

## 🔍 Verification Results

All tests include complete verification workflows, ensuring:
- ✅ Computational correctness
- ✅ Proof validity
- ✅ State consistency
- ✅ Incremental verification

---

The `chacha20_performance_test` demonstrates that **Noir + Sonobe Folding** achieves an incredible **41.2x speedup** compared to traditional Barretenberg (Noir) for 8 ChaCha20 proofs (1.7s vs 70s), and remarkably outperforms even Gnark (1.8x faster) and Expander (2.9x faster), while maintaining constant proof size and memory usage.

### 📊 Latest Benchmark Results

**Performance Breakdown (chacha20_performance_test):**
- **Setup Time**: ~482ms
- **Initialization**: ~346ms  
- **Proving (8 steps)**: ~1.7s
- **Verification**: ~18ms
- **Total Time**: ~2.54s

**Key Metrics:**
- Average proving time per step: **212ms**
- Verification time: **17.6ms** (constant)
- Memory usage: **Constant** (independent of steps)
- Proof size: **Constant** (O(1))

**Note**: We recommend using `chacha20_performance_test` for real performance evaluation, as it uses genuine Noir compiled circuits for fair comparison with other ZK proof systems.
