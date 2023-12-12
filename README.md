# noir-rsa-optimised

## Overview

This example demonstrates how to precompute particular values used for RSA decryption in a Noir circuit to optimise proving and verifying times. This is achieved by minimising the amount of division operations needed by providing the quotient to the circuit which can then perform multiplication instead, and by only doing the last exponentiation of the the RSA public exponent `e`. Essentially: `(sig * final_e) - (pubkey * quotient)`

*Note:* My assumption is that even with these optimisations, the [strong RSA assumption](https://en.wikipedia.org/wiki/Strong_RSA_assumption) still holds, because we're still performing a modulo with the public key.
Please [reach out to me](https://x.com/michaelelliot) if my assumptions about the RSA assumptions is a wrong assumption! :)

## Usage

Run tests:
```sh
nargo test --show-output
```

Prove:
```sh
nargo prove
```

Verify:
```sh
nargo verify
```

## Precompute Inputs

Run the [`./scripts/precompute_inputs.py`](./scripts/precompute_inputs.py) script to precompute the optimised circuit inputs.
