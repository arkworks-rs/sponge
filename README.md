
<h1 align="center">Cryptographic Sponges</h1>

<p align="center">
    <a href="https://github.com/arkworks-rs/sponge/blob/master/LICENSE-APACHE">
        <img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
    <a href="https://github.com/arkworks-rs/sponge/blob/master/LICENSE-MIT">
        <img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

`ark-sponge` is a Rust library that provides infrastructure for implementing 
*cryptographic sponges*. This library is released under the MIT License
and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic prototype, and in particular has not received careful code review.
This implementation is NOT ready for production use.

## Overview

A cryptographic sponge is a cryptographic primitive that has two basic operations, *absorb* and *squeeze*. A sponge
accepts byte or field element inputs through its "absorb" operation. At any time, a user can invoke the "squeeze" operation on a sponge to obtain byte or field
element outputs. The sponge is stateful, so that squeezed outputs are dependent on previous inputs and previous outputs.

The library offers infrastructure for building cryptographic sponges and using them with different types of inputs.

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version
of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via
your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo` (the standard Rust build tool) to build the library:
```bash
git clone https://github.com/arkworks-rs/sponge.git
cd sponge 
cargo build --release
```

This library comes with some unit and integration tests. Run these tests with:
```bash
cargo test
```

## License

This library is licensed under either of the following licenses, at your discretion.

 * [Apache License Version 2.0](LICENSE-APACHE)
 * [MIT License](LICENSE-MIT)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be
dual licensed as above (as defined in the Apache v2 License), without any additional terms or
conditions.

## Reference papers

[Fractal: Post-Quantum and Transparent Recursive Proofs from Holography][cos20]     
Alessandro Chiesa, Dev Ojha, Nicholas Spooner     

[POSEIDON: A New Hash Function For Zero-Knowledge Proof Systems][gkrrs19]
Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, Markus Schofnegger

[cos20]: https://eprint.iacr.org/2019/1076
[gkrrs19]: https://eprint.iacr.org/2019/458
