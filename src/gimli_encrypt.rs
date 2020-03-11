use crate::gimli_common::gimli;
use std::io;

pub struct GimliAeadEncryptIter{
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
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
        state_8[..16].clone_from_slice(&nonce);
        state_8[16..48].clone_from_slice(&key);
        gimli(&mut state);

        while associated_data.len() >= 16 {
            let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
            for i in 0..16 {
                state_8[i] ^= associated_data[i]
            }
            gimli(&mut state);
            associated_data = &associated_data[16 as usize..];
        }
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
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

        let state_8 = unsafe {std::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, 48)};
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
            let state_8 = unsafe {std::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, 48)};
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
    let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};

    // Init state with key and nonce plus first permute
    state_8[..16].clone_from_slice(nonce);
    state_8[16..48].clone_from_slice(key);
    gimli(&mut state);

    while associated_data.len() >= 16 {
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
        for i in 0..16 {
            state_8[i] ^= associated_data[i]
        }
        gimli(&mut state);
        associated_data = &associated_data[16 as usize..];
    }
    let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
    for i in 0..associated_data.len() {
        state_8[i] ^= associated_data[i]
    }
    state_8[associated_data.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    while message_len >= 16 {
        let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
        for i in 0..16 {
            state_8[i] ^= message.next().unwrap().expect("Read error on input");
            output.push(state_8[i]);
            message_len -=1;
        }
        gimli(&mut state);
    }

    let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
    for i in 0..message_len {
        state_8[i] ^= message.next().unwrap().expect("Read error on input");
        output.push(state_8[i]);
    }
    state_8[message_len as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);
    let state_8 = unsafe {std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48)};
    for i in 0..16 {
        output.push(state_8[i]);
    }

    return output;
}