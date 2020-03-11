fn rotate(x: u32, bits: usize) -> u32 {
    if bits == 0 {
        return x;
    };
    return (x << bits) | (x >> (32 - bits));
}

pub fn gimli(state: &mut [u32; 12]) {
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