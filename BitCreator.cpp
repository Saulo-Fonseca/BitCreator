// Title: BitCreator
// Author: Saulo Fonseca <fonseca@astrotown.de>
// Description: Generate Bitcoin Address
// Dependencies: You need to install GMP library
// Compile with: g++ -std=c++11 -lgmpxx -lgmp BitCreator.cpp SHA256.cpp RIPEMD160.cpp -o BitCreator

#include <stdlib.h> // srand()
#include <iomanip>  // time()
#include <gmpxx.h>  // mpz_class (bignum)
#include <iostream>
#include <string>
#include "SHA256.h"
#include "RIPEMD160.h"
using namespace std;

struct point
{
	mpz_class x;
	mpz_class y;
};

// Creates a random number with 256 bits
void genPriv(mpz_class &sk)
{
	// 1 < sk < N -1
	static mpz_class N("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
	do
	{
		sk = 0;
		for (int i=0; i<32; i++)
		{
			sk = sk << 8;
			sk += rand()%256;
		}
	} while (sk <= 0 || sk >= N);
}

// Addition operation on the elliptic curve
// See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
void add(point &p, point &q)
{
	// Define Prime
	// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
	static mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	static mpz_class lam;
	static mpz_class mod = 0;
	static mpz_class P2 = P - 2;
	
	// Calculate lambda
	if (p.x == q.x && p.y == q.y)
	{
		mpz_class opr = 2 * p.y;
		mpz_powm(mod.get_mpz_t(), opr.get_mpz_t(), P2.get_mpz_t(), P.get_mpz_t());
		lam = (3 * p.x * p.x) * mod;
	}
	else
	{
		mpz_class opr = q.x - p.x;
		mpz_powm(mod.get_mpz_t(), opr.get_mpz_t(), P2.get_mpz_t(), P.get_mpz_t());
		lam = (q.y - p.y) * mod;
	}

	// Add points
	static point r;
	r.x = lam*lam - p.x - q.x;
	r.y = lam * (p.x - r.x) - p.y;
	mpz_mod(p.x.get_mpz_t(), r.x.get_mpz_t(), P.get_mpz_t());
	mpz_mod(p.y.get_mpz_t(), r.y.get_mpz_t(), P.get_mpz_t());
}

// Convert private key to public
void priv2pub(mpz_class &sk, point &pub)
{
	// Define Base Point (G point)
	static mpz_class x("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
	static mpz_class y("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
	static point G;
	G.x = x;
	G.y = y;

	// Compute G * sk with repeated addition.
	// By using the binary representation of ski, this
	// ca be done in 256 iterations (double-and-add)
	pub.x = 0;
	pub.y = 0;
	static mpz_class bit;
	bit = 1;
	for (int i=0; i<256; i++)
	{
		mpz_class cmp = 0;
		mpz_and (cmp.get_mpz_t(), bit.get_mpz_t(), sk.get_mpz_t());
		if (cmp != 0)
		{
			if (pub.x == 0 && pub.y == 0)
			{
				pub.x = G.x;
				pub.y = G.y;
			}
			else
			{
				add(pub, G);
			}
		}
		add(G, G);
		bit = bit << 1;
	}
}

// Interface to external hash libraries
// function = 1, hash = SHA-256
// function = 2, hash = RIPEMP160
string getHash(string str, int function)
{
	// Convert string to uint8_t array
	int length = str.length() / 2;
	uint8_t *source = new uint8_t[length];
	for (int i=0; i<(int)str.length(); i+=2)
		source[i/2] = stoul(str.substr(i,2),nullptr,16);

	// Get hash of array
	int lenHash = 32;
	if (function == 2)
		lenHash = 20;
	uint8_t *hashBuf =  new uint8_t[lenHash];
	if (function == 1)
		computeSHA256(source, length, hashBuf);
	else if (function == 2)
		computeRIPEMD160(source, length, hashBuf);

	// Convert back to string
	char buf[3];
	string ret;
	for (int i=0; i<lenHash; i++)
	{
		sprintf(buf, "%02x", hashBuf[i]);
		ret += buf;
	}
	delete [] source;
	delete [] hashBuf;
	return ret;
}

// Add mainnet address and checksum
string mainnetChecksum(string mainnet, string key, bool compress)
{
	// mainnet  = 0x80 for private key and 0x00 for public key
	// key      = Hex with 32 bytes for private key and 20 for ripemd160 of public key
	// compress = If defined, generate the compressed form for private key
	mainnet += key;
	if (compress)
		mainnet += "01";
	string sha = getHash(getHash(mainnet,1),1); // sha256(sha256(x))
	string checksum = sha.substr(0,8);
	string newKey = mainnet+checksum;
	return newKey;
}

// Encode using Base58Check encoding
string encodeBase58Check(string hex)
{
	// Define scope
	static string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// Find multiple rest of division by 58
	mpz_class dec(hex.c_str(), 16);
	static mpz_class mod = 58;
	string output = "";
	while (dec>0)
	{
		mpz_class remainder;
		mpz_mod(remainder.get_mpz_t(), dec.get_mpz_t(), mod.get_mpz_t());
		dec = (dec - remainder) / 58;
		output = base58[(int)remainder.get_ui()] + output;
 	}

	// Replace all leading zeros by 1
	while (hex.substr(0,2) == "00")
	{
		output = "1" + output;
		hex = hex.substr(2);
	}
	return output;
}

// Create Private Key Wallet Import Format (WIF)
string sk2wif(string hex, bool compress)
{
	string hexCheck = mainnetChecksum("80",hex,compress);
	return encodeBase58Check(hexCheck);
}

// Convert bitcon public address to base58Check
string binary2Addr(string str)
{
	// Empty argument generate key for 1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E with almost 70 bitcoins
	string sha = getHash(str,1);
	string hexCheck = mainnetChecksum("00",getHash(sha,2),0); // ripemd160(sha256(x))
	return encodeBase58Check(hexCheck);
}

// Split X and Y values from public key
string splitXY(string key, point &pk)
{
	string x = key.substr(2,64);
	static mpz_class res;
	static mpz_class mod = 2;
	mpz_mod(res.get_mpz_t(), pk.y.get_mpz_t(), mod.get_mpz_t());
	if (res == 0)
		return "02" + x;
	return "03" + x;
}

//  ripemd160(sha256(x))
string hash160(string x)
{
	return getHash(getHash(x,1),2);
}

int main(int argc, char **argv)
{
	srand((int)time(NULL));

	// Create Private Key
	mpz_class sk;
	genPriv(sk);

	// Convert private key to WIF (compressed and uncompressed forms)
	char privBuf[65];
	gmp_sprintf(privBuf, "%Z064x", sk.get_mpz_t());
	string wif  = sk2wif(privBuf,false);
	string wifC = sk2wif(privBuf,true);

	// Get Public Key
	// This uses 97% of the runtime of the program
	point pk;
	priv2pub(sk,pk);

	// Convert public key to address (compressed and uncompressed forms)
	char pubBuf[131];
	gmp_sprintf(pubBuf, "04%Z064x%Z064x", pk.x.get_mpz_t(), pk.y.get_mpz_t());
	string pub  = binary2Addr(pubBuf);
	string pubC = binary2Addr(splitXY(pubBuf,pk));

	// Create Segwit P2SH(P2WPKH) address
	string seg = encodeBase58Check(mainnetChecksum("05",hash160("0014"+hash160(splitXY(pubBuf,pk))),false));

	// Show all addresses
	cout << "Private Key (hex)            - " << privBuf << endl;
	cout << "Private Key (WIF)            - " << wif     << endl;
	cout << "Private Key (WIF compressed) - " << wifC    << endl;
	cout << "Public Key                   - " << pub     << endl;
	cout << "Public Key compressed        - " << pubC    << endl;
	cout << "Public Segwit P2SH(P2WPKH)   - " << seg     << endl;
}

