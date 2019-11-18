use std::cmp::min;

fn rotate(x: u32, bits: usize) -> u32{
  if (bits == 0) {return x};
  return (x << bits) | (x >> (32 - bits));
}

fn gimli(state: &mut [u32; 12]){ //12*32bit = 384bit
  let mut x: u32 = 0;
  let mut y: u32 = 0;
  let mut z: u32 = 0;

  for round in (1..=24).rev()
  {
    for column in 0..=3
    {
      x = rotate(state[    column], 24);
      y = rotate(state[4 + column],  9);
      z =        state[8 + column];

      state[8 + column] = x ^ (z << 1) ^ ((y&z) << 2);
      state[4 + column] = y ^ x        ^ ((x|z) << 1);
      state[column]     = z ^ y        ^ ((x&y) << 3);
    }

    if ((round & 3) == 0) { // small swap: pattern s...s...s... etc.
      x = state[0];
      state[0] = state[1];
      state[1] = x;
      x = state[2];
      state[2] = state[3];
      state[3] = x;
    }
    if ((round & 3) == 2) { // big swap: pattern ..S...S...S. etc.
      x = state[0];
      state[0] = state[2];
      state[2] = x;
      x = state[1];
      state[1] = state[3];
      state[3] = x;
    }

    if ((round & 3) == 0) { // add constant: pattern c...c...c... etc.
      state[0] ^= (0x9e377900 | round);
    }
  }
}


static rateInBytes: u64 = 16;

pub fn Gimli_hash(mut input: &[u8], mut inputByteLen: u64, mut outputByteLen: u64) -> Vec<u8>{
  let mut output: Vec<u8> = Vec::with_capacity(outputByteLen as usize);
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };
  let mut blockSize: u64 = 0;

  // === Absorb all the input blocks ===
  while(inputByteLen > 0) {
      blockSize = min(inputByteLen, rateInBytes);
      for i in 0..blockSize{
          state_8[i as usize] ^= input[i as usize];
      }
      input = &input[blockSize as usize..];
      inputByteLen -= blockSize;

      if (blockSize == rateInBytes) {
          gimli(&mut state);
          blockSize = 0;
      }
  }

  // === Do the padding and switch to the squeezing phase ===
  state_8[blockSize as usize] ^= 0x1F;
  // Add the second bit of padding
  state_8[(rateInBytes-1) as usize] ^= 0x80;
  // Switch to the squeezing phase
  gimli(&mut state);

  // === Squeeze out all the output blocks ===
  while outputByteLen > 0 {
      blockSize = min(outputByteLen, rateInBytes);
      output.extend_from_slice(&state_8[..blockSize as usize]);
      outputByteLen -= blockSize;
      if (outputByteLen > 0){
          gimli(&mut state);
      }
  }
  return output
}

fn gimli_aead_encrypt(mut message: &[u8],mut associated_data: &[u8], nonce: &[u8; 16], key: &[u8; 32]) -> Vec<u8>{
  let mut output: Vec<u8> = Vec::new();
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };

  // Init state with key and nonce plus first permute
  state_8[..=16].clone_from_slice(nonce);
  state_8[17..=48].clone_from_slice(key);
  gimli(&mut state);

  while associated_data.len() >= 16 {
    for i in  0..16 {
      state_8[i] ^= associated_data[i]
    }
    gimli(&mut state);
    associated_data = &associated_data[16 as usize..];
  }

  for i in  0..associated_data.len() {
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

  for i in 0..message.len(){
    state_8[i] ^= message[i];
    output.push(state_8[i]);
  }
  message = &message[message.len() as usize..];
  state_8[message.len() as usize] ^= 1;
  state_8[47] ^= 1;
  gimli(&mut state);

  for i in 0..16 {
    output.push(state_8[i]);
  }

  return output
}


fn gimli_aead_decrypt(mut cipher_text: &[u8], mut associated_data: &[u8], auth_tag: &[u8; 16], nonce: &[u8; 16], key: &[u8; 32]) -> Result(Vec<u8>, Err) {
  if cipher_text.len() < 16 {
    return err;
  }
  let auth_tag = &[(cipher_text.len()-16 as usize)..];
  let mut output: Vec<u8> = Vec::new();
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };

  // Init state with key and nonce plus first permute
  state_8[..=16].clone_from_slice(nonce);
  state_8[17..=48].clone_from_slice(key);
  gimli(&mut state);

  for i in  0..associated_data.len() {
    state_8[i] ^= associated_data[i]
  }
  state_8[associated_data.len() as usize] ^= 1;
  state_8[47] ^= 1;
  gimli(&mut state);


  //Reference C code below

  while (tlen >= 16) {
    for (i = 0;i < 16;++i) m[i] = state[i] ^ c[i];
    for (i = 0;i < 16;++i) state[i] = c[i];
    gimli(state);
    c += 16;
    m += 16;
    tlen -= 16;
  }

  for (i = 0;i < tlen;++i) m[i] = state[i] ^ c[i];
  for (i = 0;i < tlen;++i) state[i] = c[i];
  c += tlen;
  m += tlen;
  state[tlen] ^= 1;
  state[47] ^= 1;
  gimli(state);

  result = 0;
  for (i = 0;i < 16;++i) result |= c[i] ^ state[i];
  result -= 1;
  result = ((int32_t) result) >> 16;

  tlen = *mlen;
  m -= tlen;
  for (i = 0;i < tlen;++i) m[i] &= result;

  return ~result;

  return Vec::new()
}


