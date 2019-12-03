use std::cmp::min;

fn rotate(x: u32, bits: usize) -> u32{
  if bits == 0 {return x};
  return (x << bits) | (x >> (32 - bits));
}

fn gimli(state: &mut [u32; 12]){ //12*32bit = 384bit
  let mut x;
  let mut y;
  let mut z;

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

    if (round & 3) == 0 { // small swap: pattern s...s...s... etc.
      x = state[0];
      state[0] = state[1];
      state[1] = x;
      x = state[2];
      state[2] = state[3];
      state[3] = x;
    }
    if (round & 3) == 2 { // big swap: pattern ..S...S...S. etc.
      x = state[0];
      state[0] = state[2];
      state[2] = x;
      x = state[1];
      state[1] = state[3];
      state[3] = x;
    }

    if (round & 3) == 0 { // add constant: pattern c...c...c... etc.
      state[0] ^= 0x9e377900 | round;
    }
  }
}


static RATE_IN_BYTES: u64 = 16;

pub fn gimli_hash(mut input: &[u8], mut input_byte_len: u64, mut output_byte_len: u64) -> Vec<u8>{
  let mut output: Vec<u8> = Vec::with_capacity(output_byte_len as usize);
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };
  let mut block_size: u64 = 0;

  // === Absorb all the input blocks ===
  while input_byte_len > 0 {
      block_size = min(input_byte_len, RATE_IN_BYTES);
      for i in 0..block_size{
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
  state_8[(RATE_IN_BYTES-1) as usize] ^= 0x80;
  // Switch to the squeezing phase
  gimli(&mut state);

  // === Squeeze out all the output blocks ===
  while output_byte_len > 0 {
      block_size = min(output_byte_len, RATE_IN_BYTES);
      output.extend_from_slice(&state_8[..block_size as usize]);
      output_byte_len -= block_size;
      if output_byte_len > 0{
          gimli(&mut state);
      }
  }
  return output
}

pub fn gimli_aead_encrypt(mut message: &[u8],mut associated_data: &[u8], nonce: &[u8; 16], key: &[u8; 32]) -> Vec<u8>{
  let mut output: Vec<u8> = Vec::new();
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };

  // Init state with key and nonce plus first permute
  state_8[..16].clone_from_slice(nonce);
  state_8[16..48].clone_from_slice(key);
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


pub fn gimli_aead_decrypt(mut cipher_text: &[u8], mut associated_data: &[u8], nonce: &[u8; 16], key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
  if cipher_text.len() < 16 {
    return Err("Cipher text too short");
  }
  // Slice off auth tag and cipher text to allow for independent handling.
  let auth_tag = &cipher_text[(cipher_text.len()-16 as usize)..];
  cipher_text = &cipher_text[..(cipher_text.len()-16 as usize)];
  println!("auth_tag: ");
  for byte in auth_tag.iter(){
    print!("{:02x?}", byte);
  }
  println!("");

  let mut output: Vec<u8> = Vec::new();
  let mut state: [u32; 12] = [0; 12];
  let state_ptr = state.as_ptr() as *mut u8;
  let state_8 = unsafe {
      std::slice::from_raw_parts_mut(state_ptr, 48)
  };

  // Init state with key and nonce plus first permute
  state_8[..16].clone_from_slice(nonce);
  state_8[16..48].clone_from_slice(key);
  gimli(&mut state);


  // Handle associated data
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

  // Handle cipher text
  while cipher_text.len() >= 16{
    for j in 0..16 {
      output.push(state_8[j] ^ cipher_text[j]);
    }
    for j in 0..16 {
      state_8[j] = cipher_text[j];
    }
    gimli(&mut state);
    cipher_text = &cipher_text[16 as usize..];
  }

  for i in  0..cipher_text.len() {output.push(state_8[i] ^ cipher_text[i])}
  // Bug in the next line?
  for i in  0..cipher_text.len() {state_8[i] = cipher_text[i]}
  state_8[cipher_text.len() as usize] ^= 1;
  state_8[47] ^= 1;
  gimli(&mut state);
  println!("state_8: ");
  for byte in state_8.iter().take(16){
    print!("{:02x?}", byte);
  }
  println!(" <<");
  println!("auth_tag: ");
  for byte in auth_tag.iter(){
    print!("{:02x?}", byte);
  }
  println!(" <<");


  // Handle tag
  let mut result: u32 = 0;
  for i in 0..16{result |= (auth_tag[i] ^ state_8[i]) as u32}

  result = result.overflowing_sub(1).0;
  result = result >> 16;
  println!("Result: {:?}", result);
  println!("output: ");
  for byte in output.iter(){
    print!("{:02x?}", byte);
  }
  println!(" <<");
  // Check tag
  let output_len = output.len();
  let last_index = output_len-1;
  for i in (0..16).rev(){
    output[last_index-i] &= result as u8; // Valid. Only the first 8 bits of result are possibly non-zero.
  }
  // println!("output: ");
  // for byte in output.iter(){
  //   print!("{:02x?}", byte);
  // }
  // println!(" <<");

  if result != 0 {return Ok(output)}
  else {
    println!("Error with >> ");
    for byte in output.iter(){
      print!("{:02x?}", byte);
    }
    println!("");
    return Err("Invalid result tag")
  }

}


