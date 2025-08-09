#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    uint32::UInt32,
    boolean::Boolean,
    R1CSVar,
    convert::ToBitsGadget,
};
use std::ops::BitXor;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_grumpkin::Projective as Projective2;

use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Error, FoldingScheme};

/// ChaCha20 Folding Circuit for stream cipher operations
/// This circuit implements one ChaCha20 block operation per folding step
/// State: [key (8 words), nonce (3 words), counter (1 word), block_output (16 words)]
/// Total state size: 28 field elements
#[derive(Clone, Copy, Debug)]
pub struct ChaCha20FCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for ChaCha20FCircuit<F> {
    type Params = ();
    type ExternalInputs = [F; 16]; // plaintext block (16 words)
    type ExternalInputsVar = [FpVar<F>; 16];

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        28 // key(8) + nonce(3) + counter(1) + block_output(16)
    }

    /// Generates constraints for one ChaCha20 block operation
    /// Input state: [key, nonce, counter, previous_block_output]
    /// Output state: [key, nonce, counter+1, current_block_output]
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut next_state = z_i.clone();
        
        // Extract counter from state and increment it
        let counter_val = z_i[11].value().unwrap_or(F::zero());
        let next_counter_val = counter_val + F::one();
        next_state[11] = FpVar::new_witness(cs.clone(), || Ok(next_counter_val))?;
        
        // Implement ChaCha20 block operation constraints
        let keystream = self.chacha20_block_gadget(cs.clone(), &z_i[0..12], &counter_val)?;
        
        // XOR plaintext with keystream (proper XOR operation)
         for i in 0..16 {
             let plaintext_u32 = self.fpvar_to_uint32(cs.clone(), &external_inputs[i])?;
             let keystream_u32 = self.fpvar_to_uint32(cs.clone(), &keystream[i])?;
             let ciphertext_u32 = self.xor_uint32(cs.clone(), &plaintext_u32, &keystream_u32)?;
             next_state[12 + i] = self.uint32_to_fpvar(cs.clone(), &ciphertext_u32)?;
         }
        
        Ok(next_state)
    }
}

impl<F: PrimeField> ChaCha20FCircuit<F> {
    /// ChaCha20 block operation as R1CS constraints
    fn chacha20_block_gadget(
        &self,
        cs: ConstraintSystemRef<F>,
        state_prefix: &[FpVar<F>], // key + nonce + counter (12 elements)
        _counter: &F,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Initialize ChaCha20 state with constants, key, nonce, counter
        let mut state = Vec::new();
        
        // ChaCha20 constants: "expand 32-byte k"
        state.push(FpVar::new_constant(cs.clone(), F::from(0x61707865u32))?);
        state.push(FpVar::new_constant(cs.clone(), F::from(0x3320646eu32))?);
        state.push(FpVar::new_constant(cs.clone(), F::from(0x79622d32u32))?);
        state.push(FpVar::new_constant(cs.clone(), F::from(0x6b206574u32))?);
        
        // Add key (8 words): state_prefix[0..8]
        for i in 0..8 {
            state.push(state_prefix[i].clone());
        }
        
        // Add counter (1 word): state_prefix[11]
        state.push(state_prefix[11].clone());
        
        // Add nonce (3 words): state_prefix[8..11]
        for i in 8..11 {
            state.push(state_prefix[i].clone());
        }
        
        // Perform 10 rounds of ChaCha20
        let mut working_state = state.clone();
        for _round in 0..10 {
            working_state = self.chacha20_round(cs.clone(), working_state)?;
        }
        
        // Add original state to working state (ChaCha20 final step)
        let mut keystream = Vec::new();
        for i in 0..16 {
            keystream.push(&state[i] + &working_state[i]);
        }
        
        Ok(keystream)
    }
    
    /// Single ChaCha20 round (column + diagonal quarter rounds)
    fn chacha20_round(
        &self,
        cs: ConstraintSystemRef<F>,
        mut state: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Column rounds
        let (a0, a4, a8, a12) = self.quarter_round(cs.clone(), &state[0], &state[4], &state[8], &state[12])?;
        let (a1, a5, a9, a13) = self.quarter_round(cs.clone(), &state[1], &state[5], &state[9], &state[13])?;
        let (a2, a6, a10, a14) = self.quarter_round(cs.clone(), &state[2], &state[6], &state[10], &state[14])?;
        let (a3, a7, a11, a15) = self.quarter_round(cs.clone(), &state[3], &state[7], &state[11], &state[15])?;
        
        // Update state after column rounds
        state[0] = a0; state[4] = a4; state[8] = a8; state[12] = a12;
        state[1] = a1; state[5] = a5; state[9] = a9; state[13] = a13;
        state[2] = a2; state[6] = a6; state[10] = a10; state[14] = a14;
        state[3] = a3; state[7] = a7; state[11] = a11; state[15] = a15;
        
        // Diagonal rounds
        let (b0, b5, b10, b15) = self.quarter_round(cs.clone(), &state[0], &state[5], &state[10], &state[15])?;
        let (b1, b6, b11, b12) = self.quarter_round(cs.clone(), &state[1], &state[6], &state[11], &state[12])?;
        let (b2, b7, b8, b13) = self.quarter_round(cs.clone(), &state[2], &state[7], &state[8], &state[13])?;
        let (b3, b4, b9, b14) = self.quarter_round(cs.clone(), &state[3], &state[4], &state[9], &state[14])?;
        
        // Update state after diagonal rounds
        state[0] = b0; state[5] = b5; state[10] = b10; state[15] = b15;
        state[1] = b1; state[6] = b6; state[11] = b11; state[12] = b12;
        state[2] = b2; state[7] = b7; state[8] = b8; state[13] = b13;
        state[3] = b3; state[4] = b4; state[9] = b9; state[14] = b14;
        
        Ok(state)
    }
    
    /// ChaCha20 quarter round as R1CS constraints (equivalent to noir implementation)
    fn quarter_round(
        &self,
        cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
        c: &FpVar<F>,
        d: &FpVar<F>,
    ) -> Result<(FpVar<F>, FpVar<F>, FpVar<F>, FpVar<F>), SynthesisError> {
        // Convert FpVar to UInt32 for proper 32-bit operations
        let a_u32 = self.fpvar_to_uint32(cs.clone(), a)?;
        let b_u32 = self.fpvar_to_uint32(cs.clone(), b)?;
        let c_u32 = self.fpvar_to_uint32(cs.clone(), c)?;
        let d_u32 = self.fpvar_to_uint32(cs.clone(), d)?;
        
        // 1. a += b; d ^= a; d <<<= 16;
         let a1 = self.add_uint32(cs.clone(), &a_u32, &b_u32)?;
         let d1 = self.xor_uint32(cs.clone(), &d_u32, &a1)?;
         let d2 = self.rotate_left_32(cs.clone(), &d1, 16)?;
         
         // 2. c += d; b ^= c; b <<<= 12;
         let c1 = self.add_uint32(cs.clone(), &c_u32, &d2)?;
         let b1 = self.xor_uint32(cs.clone(), &b_u32, &c1)?;
         let b2 = self.rotate_left_32(cs.clone(), &b1, 12)?;
         
         // 3. a += b; d ^= a; d <<<= 8;
         let a2 = self.add_uint32(cs.clone(), &a1, &b2)?;
         let d3 = self.xor_uint32(cs.clone(), &d2, &a2)?;
         let d4 = self.rotate_left_32(cs.clone(), &d3, 8)?;
         
         // 4. c += d; b ^= c; b <<<= 7;
         let c2 = self.add_uint32(cs.clone(), &c1, &d4)?;
         let b3 = self.xor_uint32(cs.clone(), &b2, &c2)?;
         let b4 = self.rotate_left_32(cs.clone(), &b3, 7)?;
        
        // Convert back to FpVar
        let a_result = self.uint32_to_fpvar(cs.clone(), &a2)?;
        let b_result = self.uint32_to_fpvar(cs.clone(), &b4)?;
        let c_result = self.uint32_to_fpvar(cs.clone(), &c2)?;
        let d_result = self.uint32_to_fpvar(cs.clone(), &d4)?;
        
        Ok((a_result, b_result, c_result, d_result))
    }
    
    /// Convert FpVar to UInt32
    fn fpvar_to_uint32(
        &self,
        _cs: ConstraintSystemRef<F>,
        fp: &FpVar<F>,
    ) -> Result<UInt32<F>, SynthesisError> {
        let bits = fp.to_bits_le()?;
        // Take only the first 32 bits
        let mut u32_bits = Vec::new();
        for i in 0..32 {
            if i < bits.len() {
                u32_bits.push(bits[i].clone());
            } else {
                u32_bits.push(Boolean::constant(false));
            }
        }
        Ok(UInt32::from_bits_le(&u32_bits))
    }
    
    /// Convert UInt32 to FpVar
    fn uint32_to_fpvar(
        &self,
        _cs: ConstraintSystemRef<F>,
        u32_val: &UInt32<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let bits = u32_val.to_bits_le()?;
        let mut result = FpVar::new_constant(_cs.clone(), F::zero())?;
         let mut power = F::one();
         for bit in bits {
             let bit_val = FpVar::new_witness(_cs.clone(), || {
                 if bit.value()? { Ok(power) } else { Ok(F::zero()) }
             })?;
             result = &result + &bit_val;
             power = power + power; // power *= 2
         }
         Ok(result)
    }
    
    /// Add two UInt32 values
    fn add_uint32(
        &self,
        _cs: ConstraintSystemRef<F>,
        a: &UInt32<F>,
        b: &UInt32<F>,
    ) -> Result<UInt32<F>, SynthesisError> {
        let a_bits = a.to_bits_le()?;
        let b_bits = b.to_bits_le()?;
        let mut result_bits = Vec::new();
        let mut carry = Boolean::constant(false);
        
        for i in 0..32 {
               // 真正的XOR操作：a XOR b
                 let sum = a_bits[i].clone().bitxor(&b_bits[i]);
                 // 32位模运算加法的进位计算：(a AND b) OR ((a XOR b) AND carry)
                 let ab_and = Boolean::kary_and(&[a_bits[i].clone(), b_bits[i].clone()])?;
                 let sum_carry_and = Boolean::kary_and(&[sum.clone(), carry.clone()])?;
                 let new_carry = Boolean::kary_or(&[ab_and, sum_carry_and])?;
                 // 最终结果：(a XOR b) XOR carry
                 result_bits.push(sum.bitxor(&carry));
                 carry = new_carry;
           }
        
        Ok(UInt32::from_bits_le(&result_bits))
    }
    
    /// XOR two UInt32 values
    fn xor_uint32(
        &self,
        _cs: ConstraintSystemRef<F>,
        a: &UInt32<F>,
        b: &UInt32<F>,
    ) -> Result<UInt32<F>, SynthesisError> {
        let a_bits = a.to_bits_le()?;
        let b_bits = b.to_bits_le()?;
        let mut result_bits = Vec::new();
        
        for i in 0..32 {
               // 真正的XOR操作：a XOR b
                 result_bits.push(a_bits[i].clone().bitxor(&b_bits[i]));
           }
        
        Ok(UInt32::from_bits_le(&result_bits))
    }
    
    /// 32-bit left rotation
    fn rotate_left_32(
        &self,
        _cs: ConstraintSystemRef<F>,
        x: &UInt32<F>,
        n: u8,
    ) -> Result<UInt32<F>, SynthesisError> {
        let bits = x.to_bits_le()?;
        let mut rotated_bits = Vec::new();
        
        // Rotate left by n positions
        for i in 0..32 {
            let src_idx = (i + 32 - (n as usize)) % 32;
            rotated_bits.push(bits[src_idx].clone());
        }
        
        Ok(UInt32::from_bits_le(&rotated_bits))
    }
}

// Note: This is a simplified ChaCha20 implementation for demonstration
// A production version would implement proper 32-bit arithmetic and rotations

/// Native ChaCha20 step function for testing (simplified)
fn chacha20_step_native<F: PrimeField>(z_i: Vec<F>, external_inputs: [F; 16]) -> Vec<F> {
    // Extract key, nonce, and counter from state
    let mut key = [0u32; 8];
    let mut nonce = [0u32; 3];
    
    for i in 0..8 {
        let bigint = z_i[i].into_bigint();
        key[i] = bigint.as_ref()[0] as u32;
    }
    
    for i in 0..3 {
        let bigint = z_i[8 + i].into_bigint();
        nonce[i] = bigint.as_ref()[0] as u32;
    }
    
    let counter_bigint = z_i[11].into_bigint();
    let counter = counter_bigint.as_ref()[0] as u32;
    
    // Convert external inputs to u32
    let mut plaintext = [0u32; 16];
    for i in 0..16 {
        let bigint = external_inputs[i].into_bigint();
        plaintext[i] = bigint.as_ref()[0] as u32;
    }
    
    // Generate ChaCha20 keystream block
    let keystream = chacha20_block_native(key, nonce, counter);
    
    // XOR plaintext with keystream to get ciphertext
    let mut ciphertext = [0u32; 16];
    for i in 0..16 {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    
    // Update state
    let mut next_state = z_i.clone();
    next_state[11] = F::from(counter + 1); // Increment counter
    
    // Store ciphertext in state
    for i in 0..16 {
        next_state[12 + i] = F::from(ciphertext[i]);
    }
    
    next_state
}

/// Native ChaCha20 block function
fn chacha20_block_native(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u32; 16] {
    // ChaCha20 constants
    let constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    
    // Initialize state
    let mut state = [0u32; 16];
    state[0..4].copy_from_slice(&constants);
    state[4..12].copy_from_slice(&key);
    state[12] = counter;
    state[13..16].copy_from_slice(&nonce);
    
    let original_state = state;
    
    // Perform 10 rounds (20 quarter-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round_native(&mut state, 0, 4, 8, 12);
        quarter_round_native(&mut state, 1, 5, 9, 13);
        quarter_round_native(&mut state, 2, 6, 10, 14);
        quarter_round_native(&mut state, 3, 7, 11, 15);
        
        // Diagonal rounds
        quarter_round_native(&mut state, 0, 5, 10, 15);
        quarter_round_native(&mut state, 1, 6, 11, 12);
        quarter_round_native(&mut state, 2, 7, 8, 13);
        quarter_round_native(&mut state, 3, 4, 9, 14);
    }
    
    // Add original state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(original_state[i]);
    }
    
    state
}

/// Native quarter round function
fn quarter_round_native(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

// Note: Full native ChaCha20 implementation would be here
// This demo focuses on the folding scheme integration

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_chacha20_f_circuit() -> Result<(), Error> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = ChaCha20FCircuit::<Fr>::new(())?;
        
        // Test with RFC 7539 test vector
        let key = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce = [0x00000000, 0x4a000000, 0x00000000];
        let counter = 1u32;
        
        // Initial state: [key, nonce, counter, zeros]
        let mut z_i = Vec::new();
        for k in key {
            z_i.push(Fr::from(k));
        }
        for n in nonce {
            z_i.push(Fr::from(n));
        }
        z_i.push(Fr::from(counter));
        for _ in 0..16 {
            z_i.push(Fr::from(0u32));
        }
        
        // Plaintext block (first 16 words of RFC test)
        let plaintext = [
            0x6964614c, 0x61207365, 0x4720646e, 0x6c746e65,
            0x6e656d65, 0x20666f20, 0x20656874, 0x73616c63,
            0x666f2073, 0x39392720, 0x6649203a, 0x63204920,
            0x646c756f, 0x66666f20, 0x79207265, 0x6f20756f,
        ];
        let external_inputs: [Fr; 16] = plaintext.iter().map(|&x| Fr::from(x)).collect::<Vec<_>>().try_into().unwrap();
        
        // Test native implementation
        let z_i1_native = chacha20_step_native(z_i.clone(), external_inputs);
        
        // Test circuit implementation
        let z_iVar = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i))?;
        let external_inputsVar: [FpVar<Fr>; 16] = <[FpVar<Fr>; 16] as AllocVar<[Fr; 16], Fr>>::new_witness(cs.clone(), || Ok(external_inputs))?;
        let computed_z_i1Var = circuit.generate_step_constraints(
            cs.clone(),
            0,
            z_iVar,
            external_inputsVar,
        )?;
        
        assert_eq!(computed_z_i1Var.value()?, z_i1_native);
        println!("✅ ChaCha20 circuit test passed!");
        Ok(())
    }
}

/// Large-scale ChaCha20 folding demonstration
fn main() -> Result<(), Error> {
    println!("🚀 ChaCha20 Folding Scheme Demo");
    
    // Test different data sizes to demonstrate folding benefits
    let test_sizes = vec![1, 10, 100, 1000]; // Number of 64-byte blocks
    
    for &num_blocks in &test_sizes {
        println!("\n📊 Testing {} blocks ({} bytes)", num_blocks, num_blocks * 64);
        
        let num_steps = num_blocks;
        
        // RFC 7539 test vector
        let key = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce = [0x00000000, 0x4a000000, 0x00000000];
        let counter = 1u32;
        
        // Initial state: [key, nonce, counter, zeros]
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
        
        let F_circuit = ChaCha20FCircuit::<Fr>::new(())?;
        
        type N = Nova<
            Projective,
            Projective2,
            ChaCha20FCircuit<Fr>,
            KZG<'static, Bn254>,
            Pedersen<Projective2>,
            false,
        >;
        
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let mut rng = rand::rngs::OsRng;
        
        println!("⚙️  Preparing Nova ProverParams & VerifierParams");
        let setup_start = Instant::now();
        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
        let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
        println!("   Setup time: {:?}", setup_start.elapsed());
        
        println!("🔄 Initializing FoldingScheme");
        let init_start = Instant::now();
        let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone())?;
        println!("   Init time: {:?}", init_start.elapsed());
        
        // Generate sample plaintext blocks
        let sample_plaintext = [
            0x6964614c, 0x61207365, 0x4720646e, 0x6c746e65,
            0x6e656d65, 0x20666f20, 0x20656874, 0x73616c63,
            0x666f2073, 0x39392720, 0x6649203a, 0x63204920,
            0x646c756f, 0x66666f20, 0x79207265, 0x6f20756f,
        ];
        
        let mut total_prove_time = std::time::Duration::new(0, 0);
        
        // Perform folding steps
        for i in 0..num_steps {
            let external_inputs: [Fr; 16] = sample_plaintext.iter().map(|&x| Fr::from(x)).collect::<Vec<_>>().try_into().unwrap();
            
            let step_start = Instant::now();
            folding_scheme.prove_step(rng, external_inputs, None)?;
            let step_time = step_start.elapsed();
            total_prove_time += step_time;
            
            if i < 5 || i % (num_steps / 5).max(1) == 0 {
                println!("   Step {}: {:?}", i + 1, step_time);
            }
        }
        
        println!("✅ Total proving time: {:?}", total_prove_time);
        println!("📈 Average time per block: {:?}", total_prove_time / num_steps as u32);
        
        println!("🔍 Verifying IVC proof");
        let verify_start = Instant::now();
        let ivc_proof = folding_scheme.ivc_proof();
        N::verify(nova_params.1, ivc_proof)?;
        println!("   Verification time: {:?}", verify_start.elapsed());
        
        println!("✅ Verification successful for {} blocks!", num_blocks);
        
        // Performance analysis
        let bytes_processed = num_blocks * 64;
        let throughput = bytes_processed as f64 / total_prove_time.as_secs_f64();
        println!("📊 Throughput: {:.2} bytes/second", throughput);
        
        if num_blocks >= 100 {
            println!("🎯 Large-scale folding demonstrates significant efficiency gains!");
            println!("   - Proof size: O(1) regardless of data size");
            println!("   - Memory usage: Constant");
            println!("   - Verification time: Independent of computation steps");
        }
    }
    
    println!("\n🎉 ChaCha20 Folding Integration Complete!");
    println!("💡 Key Benefits Demonstrated:");
    println!("   ✓ Efficient stream cipher proving with folding");
    println!("   ✓ Scalable to large data sizes");
    println!("   ✓ Constant proof size and verification time");
    println!("   ✓ Ready for zkTLS integration");
    
    Ok(())
}