//! ChaCha20 Noir Frontend Integration with Folding Schemes
//! 
//! This example demonstrates how to integrate ChaCha20 Noir circuits
//! with Sonobe's folding schemes for efficient incremental computation.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_grumpkin::Projective as G2;
use experimental_frontends::{
    noir::NoirFCircuit,
    utils::VecF,
};
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
use std::{path::Path, time::Instant};

fn main() -> Result<(), Error> {
    println!("🚀 ChaCha20 Noir Frontend Integration with Folding Schemes");
    println!("{}", "=".repeat(60));
    
    // Step 1: Load the compiled Noir circuit
    println!("\n📋 Loading Noir ChaCha20 Circuit:");
    let circuit_path = Path::new("./noir-chacha20-folding/target/chacha20_folding.json");
    
    if !circuit_path.exists() {
        eprintln!("❌ Error: Noir circuit not found at {:?}", circuit_path);
        eprintln!("Please run: cd noir-chacha20-folding && nargo compile");
        return Ok(());
    }
    
    println!("✓ Found compiled Noir circuit: {:?}", circuit_path);
    
    // Step 2: Initialize NoirFCircuit
    println!("\n🔧 Initializing Noir Frontend:");
    let start = Instant::now();
    
    // Simplified circuit state and inputs
    // External inputs: plaintext_word + step_counter = 2 elements
    const STATE_LEN: usize = 1;
    const EXT_INP_LEN: usize = 2;
    let f_circuit = NoirFCircuit::<Fr, STATE_LEN, EXT_INP_LEN>::new(circuit_path.into())
        .map_err(|e| {
            eprintln!("❌ Failed to load Noir circuit: {:?}", e);
            Error::Other("Failed to load Noir circuit".to_string())
        })?;
    
    let init_time = start.elapsed();
    println!("✓ NoirFCircuit initialized in {:?}", init_time);
    
    // Define Nova type alias
    type N = Nova<G1, G2, NoirFCircuit<Fr, STATE_LEN, EXT_INP_LEN>, KZG<'static, Bn254>, Pedersen<G2>>;
    
    // Step 3: Setup Nova folding scheme
    println!("\n⚙️ Setting up Nova Folding Scheme:");
    let start = Instant::now();
    
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = ark_std::test_rng();
    
    // Prepare initial state (simplified)
    let z_0 = vec![
        Fr::from(0), // Initial state
    ];
    
    // Setup Nova preprocessor parameters
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
    
    let setup_time = start.elapsed();
    println!("✓ Nova preprocessing completed in {:?}", setup_time);
    
    // Step 4: Initialize the folding scheme
    println!("\n🚀 Initializing Folding Scheme:");
    let start = Instant::now();
    
    let mut nova = N::init(&nova_params, f_circuit.clone(), z_0.clone())?;
    
    let nova_init_time = start.elapsed();
    println!("✓ Nova initialized in {:?}", nova_init_time);
    
    // Step 5: Perform folding steps
    println!("\n🔄 Performing Folding Steps:");
    let num_steps = 10;
    let start = Instant::now();
    
    for i in 1..=num_steps {
        // Prepare external inputs for ChaCha20 circuit with simplified interface
        // plaintext_word + step_counter = 2 elements
        let external_inputs = vec![
            Fr::from(0x6964614c + (i as u32) * 0x1000), // plaintext_word (varies with step)
            Fr::from(i as u32), // step_counter
        ];
        
        nova.prove_step(&mut rng, VecF(external_inputs), None)?;
        
        if i % 5 == 0 || i == num_steps {
            println!("  ✓ Folding step {}/{} completed", i, num_steps);
        }
    }
    
    let folding_time = start.elapsed();
    println!("✓ All {} folding steps completed in {:?}", num_steps, folding_time);
    
    // Step 6: Verify the computation
    println!("\n🔍 Verifying Computation:");
    let start = Instant::now();
    
    // Verify the IVC proof
    let ivc_proof = nova.ivc_proof();
    N::verify(nova_params.1, ivc_proof)?;
    
    let verify_time = start.elapsed();
    println!("✓ Verification completed in {:?}", verify_time);
    
    // Step 7: Performance summary
    println!("\n📊 Performance Summary:");
    let total_time = init_time + setup_time + nova_init_time + folding_time + verify_time;
    println!("  • Circuit initialization: {:?}", init_time);
    println!("  • Nova preprocessing: {:?}", setup_time);
    println!("  • Nova initialization: {:?}", nova_init_time);
    println!("  • Folding ({} steps): {:?}", num_steps, folding_time);
    println!("  • Verification: {:?}", verify_time);
    println!("  • Total time: {:?}", total_time);
    
    let avg_step_time = folding_time.as_millis() as f64 / num_steps as f64;
    println!("  • Average time per step: {:.2}ms", avg_step_time);
    
    println!("\n✅ Noir ChaCha20 + Folding Integration Successful!");
    println!("\n🎯 Key Achievements:");
    println!("  • Successfully loaded Noir ChaCha20 circuit");
    println!("  • Integrated with Nova folding scheme");
    println!("  • Performed {} incremental computation steps", num_steps);
    println!("  • Verified the entire computation");
    println!("  • Demonstrated constant-size proof generation");
    
    Ok(())
}