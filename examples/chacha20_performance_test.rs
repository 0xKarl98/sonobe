//! ChaCha20 Folding Performance Test
//! This script measures the performance of ChaCha20 folding scheme
//! and compares it with previous benchmarks

use std::time::Instant;
use ark_bn254::{Fr, G1Projective as Projective};
use ark_grumpkin::{Projective as Projective2};
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    transcript::poseidon::poseidon_canonical_config,
    frontend::FCircuit,
    FoldingScheme,
};

#[path = "chacha20_folding.rs"]
mod chacha20_folding;

use chacha20_folding::ChaCha20FCircuit;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 ChaCha20 Folding Performance Analysis");
    println!("==========================================\n");
    
    // Test configuration for 8 proofs (equivalent to previous benchmark)
    let num_proofs = 8;
    
    println!("📊 Testing {} ChaCha20 proofs with Folding Schemes", num_proofs);
    println!("Previous benchmarks:");
    println!("  - Barretenberg (Noir): ~70 seconds (8 proofs)");
    println!("  - Gnark: ~3 seconds (8 proofs)");
    println!("  - Expander (Multi-thread): ~5 seconds (8 proofs)\n");
    
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let circuit = ChaCha20FCircuit::<Fr>::new(())?;
    
    type N = Nova<
        Projective,
        Projective2,
        ChaCha20FCircuit<Fr>,
        KZG<'static, ark_bn254::Bn254>,
        Pedersen<Projective2>,
        false,
    >;
    
    let prep_param = PreprocessorParam::new(poseidon_config, circuit);
    let mut rng = rand::rngs::OsRng;
    
    // Setup phase
    println!("⚙️  Setup Phase");
    let setup_start = Instant::now();
    let nova_params = N::preprocess(&mut rng, &prep_param)?;
    let setup_time = setup_start.elapsed();
    println!("   Setup time: {:?}\n", setup_time);
    
    // Initial state setup
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    ];
    let nonce = [0x00000000, 0x4a000000, 0x00000000];
    let counter = 1u32;
    
    let mut initial_state = Vec::new();
    for k in key {
        initial_state.push(Fr::from(k));
    }
    for n in nonce {
        initial_state.push(Fr::from(n));
    }
    initial_state.push(Fr::from(counter));
    for _ in 0..16 {
        initial_state.push(Fr::from(0u32));
    }
    
    let sample_plaintext = [
        0x6964614c, 0x61207365, 0x4720646e, 0x6c746e65,
        0x6e656d65, 0x20666f20, 0x20656874, 0x73616c63,
        0x666f2073, 0x39392720, 0x6649203a, 0x63204920,
        0x646c756f, 0x66666f20, 0x79207265, 0x6f20756f,
    ];
    let external_inputs: [Fr; 16] = sample_plaintext.iter().map(|&x| Fr::from(x)).collect::<Vec<_>>().try_into().unwrap();
    
    // Initialization phase
    println!("🔄 Initialization Phase");
    let init_start = Instant::now();
    let mut folding_scheme = N::init(&nova_params, circuit, initial_state)?;
    let init_time = init_start.elapsed();
    println!("   Init time: {:?}\n", init_time);
    
    // Proving phase - measure individual steps
    println!("🔐 Proving Phase ({} steps)", num_proofs);
    let mut step_times = Vec::new();
    let total_prove_start = Instant::now();
    
    for i in 0..num_proofs {
        let step_start = Instant::now();
        folding_scheme.prove_step(rng, external_inputs, None)?;
        let step_time = step_start.elapsed();
        step_times.push(step_time);
        println!("   Step {}: {:?}", i + 1, step_time);
    }
    
    let total_prove_time = total_prove_start.elapsed();
    println!("   Total proving time: {:?}", total_prove_time);
    println!("   Average time per proof: {:?}\n", total_prove_time / num_proofs);
    
    // Verification phase
    println!("✅ Verification Phase");
    let verify_start = Instant::now();
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(nova_params.1, ivc_proof)?;
    let verify_time = verify_start.elapsed();
    println!("   Verification time: {:?}\n", verify_time);
    
    // Performance comparison
    println!("📈 Performance Comparison");
    println!("==========================================");
    println!("| ZK Proof System           | Time (8 proofs) |");
    println!("|---------------------------|------------------|");
    println!("| Barretenberg (Noir)       | ~70.0 seconds    |");
    println!("| Gnark                     | ~3.0 seconds     |");
    println!("| Expander (Multi-thread)   | ~5.0 seconds     |");
    println!("| **Sonobe Folding (Nova)** | **{:.1} seconds**   |", total_prove_time.as_secs_f64());
    println!("==========================================\n");
    
    // Calculate speedup
    let barretenberg_time = 70.0;
    let gnark_time = 3.0;
    let expander_time = 5.0;
    let folding_time = total_prove_time.as_secs_f64();
    
    println!("🚀 Speedup Analysis");
    println!("  vs Barretenberg: {:.1}x faster", barretenberg_time / folding_time);
    if folding_time < gnark_time {
        println!("  vs Gnark: {:.1}x faster", gnark_time / folding_time);
    } else {
        println!("  vs Gnark: {:.1}x slower", folding_time / gnark_time);
    }
    if folding_time < expander_time {
        println!("  vs Expander: {:.1}x faster", expander_time / folding_time);
    } else {
        println!("  vs Expander: {:.1}x slower", folding_time / expander_time);
    }
    
    println!("\n💡 Key Advantages of Folding Schemes:");
    println!("  ✓ Incremental Verification: O(1) proof size regardless of computation steps");
    println!("  ✓ Memory Efficiency: Constant memory usage");
    println!("  ✓ Composability: Easy to integrate with other circuits");
    println!("  ✓ Verification Time: {:?} (independent of computation size)", verify_time);
    
    // Additional metrics
    let total_time = setup_time + init_time + total_prove_time + verify_time;
    println!("\n📊 Detailed Breakdown:");
    println!("  Setup: {:?} ({:.1}%)", setup_time, (setup_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0);
    println!("  Init: {:?} ({:.1}%)", init_time, (init_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0);
    println!("  Proving: {:?} ({:.1}%)", total_prove_time, (total_prove_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0);
    println!("  Verification: {:?} ({:.1}%)", verify_time, (verify_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0);
    println!("  Total: {:?}", total_time);
    
    Ok(())
}