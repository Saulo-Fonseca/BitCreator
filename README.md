# BitCreator

It creates a new random private key (using /dev/random) and gets the following information of it:

- Private key (in Hex)
- Private key (in WIF format)
- Private Key (in WIF compressed format)
- BIP39 mnemonic (for HD wallets) using the private key as entropy
- Public key (in Hex)
- Public key
- Public key compressed
- Public Segwit P2SH(P2WPKH)

It uses the GMP library.

Compile the C++ version by running "make" on unix/linux systems.
