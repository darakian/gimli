# gimli
A pure rust implementation of the gimli cipher

# Status
Hash and cipher working with test vectors.  
Test vectors taken from both the paper on https://gimli.cr.yp.to  
and  
https://csrc.nist.gov/projects/lightweight-cryptography/round-2-candidates
The cipher test vectors were pull from the `LWC_AEAD_KAT_256_128.txt` file in the gimli archive.  

Test with   
```
cargo test
```

# Install
You can install gimli directly via cargo with
```
cargo install --git https://github.com/darakian/gimli gimli_rs
```
You will then have the tool `gimli_rs` in your path.

# References
The gimli cipher is described here https://gimli.cr.yp.to/ by Daniel J. Bernstein, et al.
This implementation began as a port of the reference C code and aims to be a pure rust version of the spec.

# Papers
https://gimli.cr.yp.to/papers.html#gimli-paper  

https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gimli-spec-round2.pdf
