# BitCreator

It creates a new random private key for Bitcoin (using /dev/random) and gets the following information out of it:

- Private key (in Hex)
- Private key (in WIF format)
- Private Key (in WIF compressed format)
- BIP39 mnemonic (for HD wallets) using the private key as entropy
- Public key (in Hex)
- Public key
- Public key compressed
- Public Segwit P2SH(P2WPKH)

It uses the GMP library to do calculations with 256-bit numbers.

Compile the C++ version by running "make" on unix/linux systems.
