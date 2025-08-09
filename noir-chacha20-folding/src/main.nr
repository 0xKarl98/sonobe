use noir_symmetric_crypto::ChaCha20;

// ChaCha20 Folding Circuit for IVC using Field-compatible ChaCha20
// This circuit uses the modified noir-symmetric-crypto library with Field types
fn main(
    // Current state (single Field element representing accumulated state)
    current_state: pub Field,
    // Private inputs
    plaintext_word: Field,
    step_counter: Field,
) -> pub Field {
    // Fixed ChaCha20 key (256-bit) converted to Field
    let key = [
        0x03020100 as Field, 0x07060504 as Field, 0x0b0a0908 as Field, 0x0f0e0d0c as Field,
        0x13121110 as Field, 0x17161514 as Field, 0x1b1a1918 as Field, 0x1f1e1d1c as Field
    ];
    
    // Fixed nonce (96-bit) converted to Field
    let nonce = [0x00000000 as Field, 0x4a000000 as Field, 0x00000000 as Field];
    
    // Create plaintext block using input parameters
    let mut plaintext = [0 as Field; 16];
    plaintext[0] = plaintext_word;
    plaintext[1] = step_counter;
    
    // Fill remaining plaintext with derived values for variety
    for i in 2..16 {
        plaintext[i] = plaintext_word + ((i as Field) * step_counter);
    }
    
    // Perform ChaCha20 encryption using Field arithmetic
    let ciphertext = ChaCha20(key, nonce, step_counter, plaintext);
    
    // Use first ciphertext word as result
    let result = ciphertext[0];
    
    // Accumulate with current state
    current_state + result
}

#[test]
fn test_chacha20_folding() {
    // Test with simplified parameters
    let current_state = 0 as Field;
    let plaintext_word = 0x6964614c as Field;
    let step_counter = 1 as Field;
    
    // Call the main function
    let next_state = main(current_state, plaintext_word, step_counter);
    
    // Verify that the next state is different from current state
    assert(next_state != current_state);
    
    // Verify that the computation is deterministic
    let next_state2 = main(current_state, plaintext_word, step_counter);
    assert(next_state == next_state2);
    
    // Test with different inputs should produce different output
    let next_state3 = main(current_state, plaintext_word + 1, step_counter);
    assert(next_state3 != next_state);
    
    let next_state4 = main(current_state, plaintext_word, step_counter + 1);
    assert(next_state4 != next_state);
}
