use std::cmp::min;
use std::io;

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

pub fn gimli_hash(mut input:  impl Iterator<Item = Result<u8, io::Error>>, mut input_byte_len: u64, mut output_byte_len: u64) -> Vec<u8> {
    let mut state: [u32; 12] = [0; 12];
    let state_ptr = state.as_ptr() as *mut u8;
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state_ptr, 48) };
    let mut block_size: u64 = 0;

    // === Absorb all the input blocks ===
    while input_byte_len > 0 {
        block_size = min(input_byte_len, RATE_IN_BYTES);
        for i in 0..block_size {
            state_8[i as usize] ^= input.next().unwrap().expect("Read error on input");
        }
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
    let mut output: Vec<u8> = Vec::with_capacity(output_byte_len as usize);
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

struct GimliAeadEncryptIter{
    state: [u32; 12],
    message_len: usize,
    message: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
    output_buffer: Vec<u8>,
    complete: bool,
    last_blocksize: usize,
}

impl GimliAeadEncryptIter{
    pub fn new(key: [u8; 32],
               nonce: [u8; 16],
               message_len: usize,
               message: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
               mut associated_data: &[u8]) -> Self{
        let mut state: [u32; 12] = [0; 12];
        let state_ptr = state.as_ptr() as *mut u8;
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state_ptr, 48)};
        state_8[..16].clone_from_slice(&nonce);
        state_8[16..48].clone_from_slice(&key);
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

        GimliAeadEncryptIter{
            state: state,
            message_len: message_len,
            message: message,
            output_buffer: Vec::new(),
            complete: false,
            last_blocksize: 0
        }
    }
}

impl Iterator for GimliAeadEncryptIter{
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.output_buffer.len() > 0{
            return Some(self.output_buffer.remove(0))
        }

        let state_ptr = self.state.as_ptr() as *mut u8;
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state_ptr, 48)};
        if self.message_len >= 16 {
            for i in 0..16 {
                state_8[i] ^= self.message.next().unwrap().expect("Read error on input");
                self.output_buffer.push(state_8[i]);
                self.message_len -=1;
            }
            gimli(&mut self.state);
            return Some(self.output_buffer.remove(0))
        }

        if self.message_len < 16 && self.message_len > 0 {
            self.last_blocksize = self.message_len;
            for i in 0..self.message_len {
                let foo = self.message.next().unwrap().expect("Read error on input");
                state_8[i] ^= foo;
                self.output_buffer.push(state_8[i]);
                self.message_len -=1;
            }
            return Some(self.output_buffer.remove(0))
        }

        if self.message_len == 0 && self.complete == false{
            state_8[self.last_blocksize as usize] ^= 1;
            state_8[47] ^= 1;
            gimli(&mut self.state); 
            for i in 0..16 {
                self.output_buffer.push(state_8[i]);
            }
            self.complete = true;
            return Some(self.output_buffer.remove(0))
        }

        return None

    }
}

pub fn gimli_aead_encrypt(
    mut message: impl Iterator<Item = Result<u8, io::Error>>,
    mut message_len: usize,
    mut associated_data: &[u8],
    nonce: &[u8; 16],
    key: &[u8; 32],
) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut state: [u32; 12] = [0; 12];
    let state_ptr = state.as_ptr() as *mut u8;
    let state_8 = unsafe {std::slice::from_raw_parts_mut(state_ptr, 48)};

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

    while message_len >= 16 {
        for i in 0..16 {
            state_8[i] ^= message.next().unwrap().expect("Read error on input");
            output.push(state_8[i]);
            message_len -=1;
        }
        gimli(&mut state);
    }

    for i in 0..message_len {
        state_8[i] ^= message.next().unwrap().expect("Read error on input");
        output.push(state_8[i]);
    }
    state_8[message_len as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    for i in 0..16 {
        output.push(state_8[i]);
    }

    return output;
}

struct GimliAeadDecryptIter{
    state: [u32; 12],
    cipher_message_len: usize,
    cipher_message: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
    output_buffer: Vec<u8>,
}

impl GimliAeadDecryptIter{
    pub fn new(key: [u8; 32],
               nonce: [u8; 16],
               cipher_text_len: usize,
               cipher_text: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
               mut associated_data: &[u8]) -> Self{

        let message_len = cipher_text_len - 16;
        let mut state: [u32; 12] = [0; 12];
        let state_ptr = state.as_ptr() as *mut u8;
        let state_8 = unsafe { std::slice::from_raw_parts_mut(state_ptr, 48) };

        // Init state with key and nonce plus first permute
        state_8[..16].clone_from_slice(&nonce);
        state_8[16..48].clone_from_slice(&key);
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

        GimliAeadDecryptIter{
            state: state,
            cipher_message_len: message_len,
            cipher_message: cipher_text,
            output_buffer: Vec::new(),
        }
    }
}

impl Iterator for GimliAeadDecryptIter{
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.output_buffer.len() > 0{
            return Some(self.output_buffer.remove(0))
        }
        let state_ptr = self.state.as_ptr() as *mut u8;
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state_ptr, 48)};

        if self.cipher_message_len >= 16 {
            for i in 0..16 {
                let current_byte = self.cipher_message.next().unwrap().expect("Read error on input");
                self.output_buffer.push(state_8[i] ^ current_byte);
                state_8[i] = current_byte;
                self.cipher_message_len -=1;
            }
            gimli(&mut self.state);
            return Some(self.output_buffer.remove(0))
        }

        if self.cipher_message_len <= 15 && self.cipher_message_len > 0 {
            for i in 0..self.cipher_message_len {
                let current_byte = self.cipher_message.next().unwrap().expect("Read error on input");
                self.output_buffer.push(state_8[i] ^ current_byte);
                state_8[i] = current_byte;
            }
            state_8[self.cipher_message_len as usize] ^= 1;
            state_8[47] ^= 1;
            gimli(&mut self.state);
            self.cipher_message_len = 0;
            // Handle tag
            let mut result: u32 = 0;
            for i in 0..16 {
                let current_byte = self.cipher_message.next().unwrap().expect("Read error on input");
                result |= (current_byte ^ state_8[i]) as u32;
            }
            result = result.overflowing_sub(1).0;
            result = result >> 16;
            assert_ne!(result, 0);
            match self.output_buffer.len() {
                0 => return None,
                _ => return Some(self.output_buffer.remove(0)),
            }
        }
        None
    }
}

pub fn gimli_aead_decrypt(
    mut cipher_text: impl Iterator<Item = Result<u8, io::Error>>,
    cipher_text_len: usize,
    mut associated_data: &[u8],
    nonce: &[u8; 16],
    key: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if cipher_text_len < 16 {
        return Err("Cipher text too short");
    }

    let mut cipher_message_len = cipher_text_len - 16;
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
    while cipher_message_len >= 16 {
        for j in 0..16 {
            let current_byte = cipher_text.next().unwrap().expect("Read error on input");
            output.push(state_8[j] ^ current_byte);
            state_8[j] = current_byte;
        }
        gimli(&mut state);
        cipher_message_len-=16;
    }

    for i in 0..cipher_message_len {
        let current_byte = cipher_text.next().unwrap().expect("Read error on input");
        output.push(state_8[i] ^ current_byte);
        state_8[i] = current_byte;
    }
    state_8[cipher_message_len as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    // Handle tag
    let mut result: u32 = 0;
    for i in 0..16 {
        let current_byte = cipher_text.next().unwrap().expect("Read error on input");
        result |= (current_byte ^ state_8[i]) as u32
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
    mod cipher_test;
    use crate::tests::cipher_test::cipher_test::get_cipher_vectors;

    #[test]
    fn hash_test(){
        // (Plaintext, hash, hash_len)
        let hash_vectors = vec![
            ("There's plenty for the both of us, may the best Dwarf win.", "4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8", 32, ),
            ("If anyone was to ask for my opinion, which I note they're not, I'd say we were taking the long way around.", "ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c", 32),
            ("Speak words we can all understand!", "8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267", 32),
            ("It's true you don't see many Dwarf-women. And in fact, they are so alike in voice and appearance, that they are often mistaken for Dwarf-men.  And this in turn has given rise to the belief that there are no Dwarf-women, and that Dwarves just spring out of holes in the ground! Which is, of course, ridiculous.", "ebe9bfc05ce15c73336fc3c5b52b01f75cf619bb37f13bfc7f567f9d5603191a", 32),
            ("", "b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67", 32)
            ];

        for vec in hash_vectors.iter(){
            let input_len = vec.0.len() as u64;
            assert_eq!(vec.1, gimli_hash(
                vec.0
                    .to_string()
                    .into_bytes()
                    .into_iter()
                    .map(|x| Ok(x)),
                input_len,
                vec.2).iter().map(|x| format!("{:02x?}", x)).collect::<String>()
            )
        }
    }

    #[test]
    fn test_cipher(){

        // Test key = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
        // Test nonce = 000102030405060708090A0B0C0D0E0F
        let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        // (Plaintext, AD, Ciphertext)
        let cipher_vectors = get_cipher_vectors();

        for vec in cipher_vectors.iter(){
            let pt_len = vec.0.len();
            let pt = vec.0.clone().into_iter().map(|x| Ok(x));
            let assoc_d = &vec.1;
            let ct = vec.2.clone().into_iter().map(|x| Ok(x));
            let ct_len = vec.2.len();

            let ge_iter = GimliAeadEncryptIter::new(
                key,
                nonce,
                pt_len,
                Box::new(pt.clone()),
                assoc_d);
            let result: Vec<u8> = ge_iter.collect();
            assert_eq!(vec.2, result);


            assert_eq!(vec.2, gimli_aead_encrypt(
                pt.clone(),
                pt_len,
                assoc_d,
                &nonce,
                &key));

            let gd_iter = GimliAeadDecryptIter::new(
                key,
                nonce,
                ct_len,
                Box::new(ct.clone()),
                assoc_d,
                );
            println!("Testing ct:{:?}, pt:{:?}", ct, pt);
            let pt: Vec<u8> = gd_iter.collect();
            assert_eq!(pt, pt);
            assert_eq!(pt, gimli_aead_decrypt(
                ct,
                ct_len,
                &vec.1,
                &nonce,
                &key).expect("Error in test decryption"));
        }
    }
}






