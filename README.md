# gimli
A pure rust implementation of the gimli cipher

# Status
Hash function working with cipher test vectors. Test with   
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

# Paper
https://gimli.cr.yp.to/papers.html#gimli-paper
