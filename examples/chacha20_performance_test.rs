//! ChaCha20 Noir Circuit Folding Performance Test
//! This script measures the performance of ChaCha20 Noir circuit with folding scheme
//! and compares it with traditional ZK proof systems (Barretenberg, Gnark, Expander)

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use std::{path::Path, time::Instant};
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_grumpkin::Projective as G2;
use experimental_frontends::{
    noir::NoirFCircuit,
    utils::VecF,
};
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    transcript::poseidon::poseidon_canonical_config,
    frontend::FCircuit,
    Error, FoldingScheme,
};

fn main() -> Result<(), Error> {
    println!("🚀 ChaCha20 Noir Circuit Folding Performance Analysis");
    println!("====================================================\n");
    
    // Test configuration for 8 proofs (equivalent to previous benchmark)
    let num_proofs = 8;
    
    println!("📊 Testing {} ChaCha20 proofs with Noir + Sonobe Folding", num_proofs);
    println!("Comparing against traditional ZK proof systems:");
    println!("  - Barretenberg (Noir): ~70 seconds (8 proofs)");
    println!("  - Gnark: ~3 seconds (8 proofs)");
    println!("  - Expander (Multi-thread): ~5 seconds (8 proofs)\n");
    
    // Step 1: Load the compiled Noir circuit
    println!("📋 Loading Noir ChaCha20 Circuit:");
    let circuit_path = Path::new("./noir-chacha20-folding/target/chacha20_folding.json");
    
    if !circuit_path.exists() {
        eprintln!("❌ Error: Noir circuit not found at {:?}", circuit_path);
        eprintln!("Please run: cd noir-chacha20-folding && nargo compile");
        return Ok(());
    }
    
    println!("✓ Found compiled Noir circuit: {:?}", circuit_path);
    
    // Step 2: Initialize NoirFCircuit
    const STATE_LEN: usize = 1;
    const EXT_INP_LEN: usize = 2;
    let f_circuit = NoirFCircuit::<Fr, STATE_LEN, EXT_INP_LEN>::new(circuit_path.into())
        .map_err(|e| {
            eprintln!("❌ Failed to load Noir circuit: {:?}", e);
            Error::Other("Failed to load Noir circuit".to_string())
        })?;
    
    // Define Nova type alias
    type N = Nova<G1, G2, NoirFCircuit<Fr, STATE_LEN, EXT_INP_LEN>, KZG<'static, Bn254>, Pedersen<G2>>;
    
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = ark_std::test_rng();
    
    // Setup phase
    println!("⚙️  Setup Phase");
    let setup_start = Instant::now();
    
    // Prepare initial state (simplified for Noir circuit)
    let z_0 = vec![
        Fr::from(0), // Initial state
    ];
    
    // Setup Nova preprocessor parameters
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
    let setup_time = setup_start.elapsed();
    println!("   Setup time: {:?}\n", setup_time);
    
    // Initialization phase
    println!("🔄 Initialization Phase");
    let init_start = Instant::now();
    let mut folding_scheme = N::init(&nova_params, f_circuit.clone(), z_0.clone())?;
    let init_time = init_start.elapsed();
    println!("   Init time: {:?}\n", init_time);
    
    // Proving phase - measure individual steps
    println!("🔐 Proving Phase ({} steps)", num_proofs);
    let mut step_times = Vec::new();
    let total_prove_start = Instant::now();
    
    for i in 0..num_proofs {
        let step_start = Instant::now();
        
        // Prepare external inputs for ChaCha20 circuit with simplified interface
        // plaintext_word + step_counter = 2 elements
        let external_inputs = vec![
            Fr::from(0x6964614c + (i as u32) * 0x1000), // plaintext_word (varies with step)
            Fr::from((i + 1) as u32), // step_counter
        ];
        
        folding_scheme.prove_step(&mut rng, VecF(external_inputs), None)?;
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
    println!("| ZK Proof System              | Time (8 proofs) |");
    println!("|------------------------------|------------------|");
    println!("| Barretenberg (Noir)          | ~70.0 seconds    |");
    println!("| Gnark                        | ~3.0 seconds     |");
    println!("| Expander (Multi-thread)      | ~5.0 seconds     |");
    println!("| **Noir + Sonobe Folding**    | **{:.1} seconds**   |", total_prove_time.as_secs_f64());
    println!("==========================================\n");
    
    // Calculate speedup
    let barretenberg_time = 70.0;
    let gnark_time = 3.0;
    let expander_time = 5.0;
    let folding_time = total_prove_time.as_secs_f64();
    
    println!("🚀 Speedup Analysis (Noir + Sonobe Folding vs Traditional):");
    if folding_time < barretenberg_time {
        println!("  vs Barretenberg (Noir): {:.1}x faster", barretenberg_time / folding_time);
    } else {
        println!("  vs Barretenberg (Noir): {:.1}x slower", folding_time / barretenberg_time);
    }
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
    
    println!("\n💡 Key Advantages of Noir + Folding Schemes:");
    println!("  ✓ Incremental Verification: O(1) proof size regardless of computation steps");
    println!("  ✓ Memory Efficiency: Constant memory usage");
    println!("  ✓ Noir Integration: Direct use of Noir circuits without Rust reimplementation");
    println!("  ✓ Composability: Easy to integrate with other circuits");
    println!("  ✓ Verification Time: {:?} (independent of computation size)", verify_time);
    
    println!("\n🎯 This benchmark uses genuine Noir compiled circuits, providing");
    println!("    a fair comparison with traditional Noir (Barretenberg) performance.");
    
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