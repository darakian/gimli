use std::cmp::min;

fn rotate(x: u32, bits: usize) -> u32 {
    if bits == 0 {
        return x;
    };
    return (x << bits) | (x >> (32 - bits));
}

fn gimli(state: &mut [u32; 12]) {
    //12*32bit = 384bit
    let mut x;
    let mut y;
    let mut z;

    for round in (1..=24).rev() {
        for column in 0..=3 {
            x = rotate(state[column], 24);
            y = rotate(state[4 + column], 9);
            z = state[8 + column];

            state[8 + column] = x ^ (z << 1) ^ ((y & z) << 2);
            state[4 + column] = y ^ x ^ ((x | z) << 1);
            state[column] = z ^ y ^ ((x & y) << 3);
        }

        if (round & 3) == 0 {
            // small swap: pattern s...s...s... etc.
            x = state[0];
            state[0] = state[1];
            state[1] = x;
            x = state[2];
            state[2] = state[3];
            state[3] = x;
        }
        if (round & 3) == 2 {
            // big swap: pattern ..S...S...S. etc.
            x = state[0];
            state[0] = state[2];
            state[2] = x;
            x = state[1];
            state[1] = state[3];
            state[3] = x;
        }

        if (round & 3) == 0 {
            // add constant: pattern c...c...c... etc.
            state[0] ^= 0x9e377900 | round;
        }
    }
}

static RATE_IN_BYTES: u64 = 16;

pub fn gimli_hash(mut input: &[u8], mut input_byte_len: u64, mut output_byte_len: u64) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(output_byte_len as usize);
    let mut state: [u32; 12] = [0; 12];
    let state_ptr = state.as_ptr() as *mut u8;
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state_ptr, 48) };
    let mut block_size: u64 = 0;

    // === Absorb all the input blocks ===
    while input_byte_len > 0 {
        block_size = min(input_byte_len, RATE_IN_BYTES);
        for i in 0..block_size {
            state_8[i as usize] ^= input[i as usize];
        }
        input = &input[block_size as usize..];
        input_byte_len -= block_size;

        if block_size == RATE_IN_BYTES {
            gimli(&mut state);
            block_size = 0;
        }
    }

    // === Do the padding and switch to the squeezing phase ===
    state_8[block_size as usize] ^= 0x1F;
    // Add the second bit of padding
    state_8[(RATE_IN_BYTES - 1) as usize] ^= 0x80;
    // Switch to the squeezing phase
    gimli(&mut state);

    // === Squeeze out all the output blocks ===
    while output_byte_len > 0 {
        block_size = min(output_byte_len, RATE_IN_BYTES);
        output.extend_from_slice(&state_8[..block_size as usize]);
        output_byte_len -= block_size;
        if output_byte_len > 0 {
            gimli(&mut state);
        }
    }
    return output;
}

pub fn gimli_aead_encrypt(
    mut message: &[u8],
    mut associated_data: &[u8],
    nonce: &[u8; 16],
    key: &[u8; 32],
) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut state: [u32; 12] = [0; 12];
    let state_ptr = state.as_ptr() as *mut u8;
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state_ptr, 48) };

    // Init state with key and nonce plus first permute
    state_8[..16].clone_from_slice(nonce);
    state_8[16..48].clone_from_slice(key);
    gimli(&mut state);

    while associated_data.len() >= 16 {
        for i in 0..16 {
            state_8[i] ^= associated_data[i]
        }
        gimli(&mut state);
        associated_data = &associated_data[16 as usize..];
    }

    for i in 0..associated_data.len() {
        state_8[i] ^= associated_data[i]
    }
    state_8[associated_data.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    while message.len() >= 16 {
        for i in 0..16 {
            state_8[i] ^= message[i];
            output.push(state_8[i]);
        }
        gimli(&mut state);
        message = &message[16 as usize..];
    }

    for i in 0..message.len() {
        state_8[i] ^= message[i];
        output.push(state_8[i]);
    }
    state_8[message.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    for i in 0..16 {
        output.push(state_8[i]);
    }

    return output;
}

pub fn gimli_aead_decrypt(
    mut cipher_text: &[u8],
    mut associated_data: &[u8],
    nonce: &[u8; 16],
    key: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if cipher_text.len() < 16 {
        return Err("Cipher text too short");
    }
    // Slice off auth tag and cipher text to allow for independent handling.
    let auth_tag = &cipher_text[(cipher_text.len() - 16 as usize)..];
    cipher_text = &cipher_text[..(cipher_text.len() - 16 as usize)];

    let mut output: Vec<u8> = Vec::new();
    let mut state: [u32; 12] = [0; 12];
    let state_ptr = state.as_ptr() as *mut u8;
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state_ptr, 48) };

    // Init state with key and nonce plus first permute
    state_8[..16].clone_from_slice(nonce);
    state_8[16..48].clone_from_slice(key);
    gimli(&mut state);

    // Handle associated data
    while associated_data.len() >= 16 {
        for i in 0..16 {
            state_8[i] ^= associated_data[i]
        }
        gimli(&mut state);
        associated_data = &associated_data[16 as usize..];
    }
    for i in 0..associated_data.len() {
        state_8[i] ^= associated_data[i]
    }
    state_8[associated_data.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    // Handle cipher text
    while cipher_text.len() >= 16 {
        for j in 0..16 {
            output.push(state_8[j] ^ cipher_text[j]);
        }
        for j in 0..16 {
            state_8[j] = cipher_text[j];
        }
        gimli(&mut state);
        cipher_text = &cipher_text[16 as usize..];
    }

    for i in 0..cipher_text.len() {
        output.push(state_8[i] ^ cipher_text[i])
    }
    for i in 0..cipher_text.len() {
        state_8[i] = cipher_text[i]
    }
    state_8[cipher_text.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    // Handle tag
    let mut result: u32 = 0;
    for i in 0..16 {
        result |= (auth_tag[i] ^ state_8[i]) as u32
    }
    result = result.overflowing_sub(1).0;
    result = result >> 16;

    for i in 0..output.len() {
        output[i] &= result as u8; // Valid. Only the first 8 bits of result are possibly non-zero.
    }

    if result != 0 {
        return Ok(output);
    } else {
        println!("Error with >> ");
        for byte in output.iter() {
            print!("{:02x?}", byte);
        }
        println!("");
        return Err("Invalid result tag");
    }
}

#[cfg(test)]
mod tests{
    use super::*;


    #[test]
    fn hash_test(){
    
        let hash_vectors = vec![
            ("There's plenty for the both of us, may the best Dwarf win.", "4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8", 32, ),
            ("If anyone was to ask for my opinion, which I note they're not, I'd say we were taking the long way around.", "ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c", 32),
            ("Speak words we can all understand!", "8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267", 32),
            ("It's true you don't see many Dwarf-women. And in fact, they are so alike in voice and appearance, that they are often mistaken for Dwarf-men.  And this in turn has given rise to the belief that there are no Dwarf-women, and that Dwarves just spring out of holes in the ground! Which is, of course, ridiculous.", "ebe9bfc05ce15c73336fc3c5b52b01f75cf619bb37f13bfc7f567f9d5603191a", 32),
            ("", "b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67", 32)
            ];

        for vec in hash_vectors.iter(){
            assert_eq!(vec.1, gimli_hash(
                vec.0.as_bytes(),
                vec.0.len() as u64,
                vec.2).iter().map(|x| format!("{:02x?}", x)).collect::<String>()
            )
        }
    }
}
