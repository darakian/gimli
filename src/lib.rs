use std::cmp::min;

fn rotate(x: u32, bits: usize) -> u32{
  if (bits == 0) {return x};
  return (x << bits) | (x >> (32 - bits));
}

pub fn gimli(state: &mut [u32; 12]){ //12*32bit = 384bit
  let mut x: u32 = 0;
  let mut y: u32 = 0;
  let mut z: u32 = 0;

  for round in (0..24).rev()
  {
    for column in 0..4
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

pub fn Gimli_hash(input: &[u8], mut inputByteLen: u64, mut outputByteLen: u64) -> Vec<u8>{
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
        let input = &input[blockSize as usize..];
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            gimli(&mut state);
            blockSize = 0;
        }
    }

    // === Do the padding and switch to the squeezing phase ===
    state_8[blockSize as usize] ^= 0x1F;
    println!(">> {:x?}", state_8);
    // Add the second bit of padding
    state_8[(rateInBytes-1) as usize] ^= 0x80;
    println!(">> {:x?}", state_8);
    // Switch to the squeezing phase
    gimli(&mut state);
    println!(">> {:x?}", state_8);

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
