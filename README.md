# Implementation

This repository contains a Rust implementation of Hybrid-WireGuard and PQ-WireGuard from the paper "A Tale of Two Worlds, a Story of WireGuard Hybridization".

All results are currently reproductible on a fresh Ubuntu Server LTS 24.04.2 setup[^0].

## Licence

GNU General Public License v3[^1].


## Prerequisites

This project uses the following:
* Clang version 18.1.3[^2]
* Rust version 1.87.0[^3]

To install them, run:
```
sh run_install-dep-rust-clang.sh
``` 

Then ```$HOME/.cargo/env``` shall be sourced:

```
. "$HOME/.cargo/env"
```

## Content

The implementation is based on the WireGuard Rust implementation[^3]. It includes the original implementation, as well as the implemenations of PQ-WireGuard^* and Hybrid-WireGuard defined in paper.


## Usage

To run the benchmarks, run for example:
```
cargo build
cargo run -- -b 100
```
where `100` is the number of executions for each handshake to compute the average execution time. 

Besides that, the configuration is similar to the one in the original WireGuard implementation, as specified in the corresponding README[^4].


## References

[^0]: https://ubuntu.com/download/server
[^1]: https://www.gnu.org/licenses/gpl-3.0.html
[^2]: https://clang.llvm.org/
[^3]: https://www.rust-lang.org/
[^4]: https://github.com/WireGuard/wireguard-rs
[^5]: https://github.com/WireGuard/wireguard-rs/blob/master/README.md