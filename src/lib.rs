use crate::gimli_common::gimli;
use crate::gimli_decrypt::{gimli_aead_decrypt, GimliAeadDecryptIter};
use crate::gimli_encrypt::{gimli_aead_encrypt, GimliAeadEncryptIter};
use std::cmp::min;
use std::io;

pub mod gimli_encrypt;
pub mod gimli_decrypt;
pub mod gimli_common;

static RATE_IN_BYTES: u64 = 16;

pub fn gimli_hash(mut input:  impl Iterator<Item = Result<u8, io::Error>>, mut input_byte_len: u64, mut output_byte_len: u64) -> Vec<u8> {
    let mut state: [u32; 12] = [0; 12];
    let mut block_size: u64 = 0;

    while input_byte_len > 0 {
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
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

    let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
    state_8[block_size as usize] ^= 0x1F;
    state_8[(RATE_IN_BYTES - 1) as usize] ^= 0x80;
    gimli(&mut state); // Calling gimli invalidates other references to state. ie stats_8

    let mut output: Vec<u8> = Vec::with_capacity(output_byte_len as usize);
    while output_byte_len > 0 {
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
        block_size = min(output_byte_len, RATE_IN_BYTES);
        output.extend_from_slice(&state_8[..block_size as usize]);
        output_byte_len -= block_size;
        if output_byte_len > 0 {
            gimli(&mut state);
        }
    }
    return output;
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






