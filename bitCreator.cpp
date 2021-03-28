// Title: BitCreator
// Author: Saulo Fonseca <fonseca@astrotown.de>
// Description: Generate Bitcoin Address
// Dependencies: You need to install GMP library
// Compile with: g++ -std=c++11 -lgmpxx -lgmp BitCreator.cpp SHA256.cpp RIPEMD160.cpp -o BitCreator

#include <string>
#include <iostream>
#include <sys/ioctl.h>
#include <gmpxx.h>        // mpz_class (bignum)
#include <fcntl.h>        // O_RDONLY
#include <unistd.h>       // READ, CLOSE
#include "BIP39.hpp"
#include "SHA256.h"
#include "RIPEMD160.h"
#include "GaloisField.hpp"
using namespace std;

struct point
{
	GF x;
	GF y;
};

// Values for secp256k1
class Curve
{
public:
	mpz_class N;
	mpz_class P;
	point G;
	Curve() // Constructor
	{
		mpz_class N("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
		mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
		mpz_class x("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
		mpz_class y("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
		this->G.x = GF(x,P);
		this->G.y = GF(y,P);
		this->N = N;
		this->P = P;
	}
};
Curve secp256k1;

// Get n bytes from /dev/random as hex string
string readDevRandom(int n)
{
	// Define some vars
	string hex;
	char buf[3];
	bool success = false;

	// Open /dev/urandom
#ifdef __APPLE__
	// Apple /dev/random uses the Yarrow CSPRNG that does not offer an entropy check
	do
	{
		int rnd = open("/dev/random", O_RDONLY);
		if (rnd >=0)
		{
			unsigned char c;
			for (int i=0; i<n; i++)
			{
				read(rnd,&c,1);
				sprintf(buf,"%02hhx",c);
				hex += buf;
			}
			close(rnd);
			success = true;
		}
		else
		{
			cout << "/dev/random is not available or does not have enough entropy! Trying again..." << endl;
		}
	} while (success == false);
#else
	unsigned int entropy = 0;
	do
	{
		int rnd = open("/dev/random", O_RDONLY);
		if (rnd >=0 && !ioctl(rnd, 2147766784, &entropy) && (entropy >= 32))
		{
			unsigned char c;
			for (int i=0; i<n; i++)
			{
				read(rnd,&c,1);
				sprintf(buf,"%02hhx",c);
				hex += buf;
			}
			close(rnd);
			success = true;
		}
		else
		{
			cout << "/dev/random is not available or does not have enough entropy! Trying again..." << endl;
		}
	} while (success == false);
#endif
	return hex;
}

// Creates a random number with 256 bits
GF genPriv()
{
	// 1 < sk < N -1
	mpz_class key;
	do
	{
		key = mpz_class(readDevRandom(32),16);
	} while (key <= 0 || key >= secp256k1.N);
	return GF(key,secp256k1.P);
}

// Addition operation on the elliptic curve
// See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
point add(point &p, point &q)
{
	// Calculate lambda
	GF lambda;
	if (p.x == q.x && p.y == q.y)
	{
		lambda = ( p.x.pow(2) * 3 ) / ( p.y * 2 );
	}
	else
	{
		lambda = (q.y - p.y) / (q.x - p.x);
	}

	// Add points
	point r;
	r.x = lambda.pow(2) - p.x - q.x;
	r.y = lambda * (p.x - r.x) - p.y;
	return r;
}

// Convert private key to public
point priv2pub(GF &sk, point *Q=NULL)
{
	// Copy generator
	point G;
	if (Q == NULL)
	{
		G.x = secp256k1.G.x;
		G.y = secp256k1.G.y;	
	}
	else
	{
		G.x = Q->x;
		G.y = Q->y;
	}

	// Pre calculate all multiples of G
	static bool calculated = false;
	static point Gs[256];
	if (!calculated)
	{
		for (int i=0; i<256; i++)
		{
			Gs[i].x = G.x;
			Gs[i].y = G.y;
			G = add(G, G);
		}
		calculated = true;
	}

	// Compute G * sk
	point pub;
	pub.x = GF(0,secp256k1.P);
	pub.y = GF(0,secp256k1.P);
	mpz_class bit;
	bit = 1;
	for (int i=0; i<256; i++)
	{
		mpz_class cmp = 0;
		mpz_and (cmp.get_mpz_t(), bit.get_mpz_t(), sk.getNum().get_mpz_t());
		if (cmp != 0)
		{
			if (pub.x == 0 && pub.y == 0)
			{
				pub.x = Gs[i].x;
				pub.y = Gs[i].y;
			}
			else
			{
				pub = add(pub, Gs[i]);
			}
		}
		bit = bit << 1;
	}
	return pub;
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
string mainnetChecksum(string mainnet, const string &key, bool compress)
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

// Encode using Base58Check
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

// Decode Base58 from WIF
string decodeBase58(string wif)
{
	// Define scope of Base58
	static string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// Recover hex from WIF
	mpz_class n = 0;
	while (wif.length() > 0)
	{
		n *= 58;
		int idx = base58.find(wif.substr(0,1));
		if (idx<0)
		{
			cout << "Wrong WIF format. This is not Base58!" << endl;
			return "";
		}
		n += idx;
		wif = wif.substr(1);
	}
	static char buf[77];
	gmp_sprintf(buf, "%Z076x", n.get_mpz_t());
	return buf;
}

// Remove mainnet and checksum
string remMainCheck(string hex)
{
	// Check if hex from WIF is compressed
	bool compressed = false;
	if (hex.substr(0,2) != "00")
		compressed = true;
	if (!compressed)
		hex = hex.substr(2);

	// Remove checksum
	string check = hex.substr(hex.length()-8);
	hex = hex.substr(0,hex.length()-8);
	string sha = getHash(getHash(hex,1),1); // sha256(sha256(x))
	string checksum = sha.substr(0,8);
	if (checksum != check)
		cout << "Checksum is wrong!" << endl;
	
	// Remove mainnet
	if (hex.substr(0,2) == "80")
		hex = hex.substr(2);
	else
		cout << "This is not a WIF!" << endl;

	// Remove compressed marker
	return hex.substr(0,64);
}

// Convert WIF address to private key
GF wif2sk(const string &wif)
{
	string hex = decodeBase58(wif);
	hex = remMainCheck(hex);
	return GF(mpz_class(hex,16),secp256k1.P);
}

// Create Private Key Wallet Import Format (WIF)
string sk2wif(const string &hex, bool compress)
{
	string hexCheck = mainnetChecksum("80",hex,compress);
	return encodeBase58Check(hexCheck);
}

// Convert bitcon public address to base58Check
string binary2Addr(const string &str)
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
	mpz_mod(res.get_mpz_t(), pk.y.getNum().get_mpz_t(), mod.get_mpz_t());
	if (res == 0)
		return "02" + x;
	return "03" + x;
}

// Check if a point is on the curve
bool onCurve(point p)
{
	if (p.x.getPrime() == 0 or p.y.getPrime() == 0)
		return false;
	return (p.y.pow(2) - p.x.pow(3) - 7).getNum() == 0;
}

//  ripemd160(sha256(x))
string hash160(const string &x)
{
	return getHash(getHash(x,1),2);
}

// Convert private key to BIP39 mnemonic
string toBIP39(char* privBuf)
{
	// Create checksum
	string sha256 = getHash(privBuf,1);
	string checksum = sha256.substr(0,2);
	string entropy = privBuf + checksum;

	// Get mnemonic
	string mnemonic;
	mpz_t n, next11, b11;
	mpz_init(n);
	mpz_init(next11);
	mpz_init(b11);
	mpz_set_str(n,entropy.c_str(),16);
	mpz_set_ui(b11,2047);
	for (int i=0; i<24; i++)
	{
		mpz_and(next11,n,b11);
		mnemonic = getMnemonic(mpz_get_ui(next11)) + " " + mnemonic;
		mpz_fdiv_q_2exp(n,n,11); // shift >> 11
	}
	return mnemonic;
}

int main(int argc, char **argv)
{
	// Create Private Key
	GF sk = genPriv();

	// Convert private key to WIF (compressed and uncompressed forms)
	char privBuf[66];
	gmp_sprintf(privBuf, "%Z064x", sk.getNum().get_mpz_t());
	string wif  = sk2wif(privBuf,false);
	string wifC = sk2wif(privBuf,true);

	// Get Public Key
	point pk = priv2pub(sk);

	// Convert public key to address (compressed and uncompressed forms)
	char pubBuf[131];
	gmp_sprintf(pubBuf, "04%Z064x%Z064x", pk.x.getNum().get_mpz_t(), pk.y.getNum().get_mpz_t());
	string pub  = binary2Addr(pubBuf);
	string pubC = binary2Addr(splitXY(pubBuf,pk));

	// Create Segwit P2SH(P2WPKH) address
	string seg = encodeBase58Check(mainnetChecksum("05",hash160("0014"+hash160(splitXY(pubBuf,pk))),false));

	// Show all addresses
	cout << "Private Key (hex)            - " << privBuf << endl;
	cout << "Private Key (WIF)            - " << wif     << endl;
	cout << "Private Key (WIF compressed) - " << wifC    << endl;
	cout << "BIP39 mnemonic (HD wallet)   - " << toBIP39(privBuf) << endl; 
	printf( "Public Key (hex)             - %s\n",pubBuf);
	cout << "Public Key                   - " << pub     << endl;
	cout << "Public Key compressed        - " << pubC    << endl;
	cout << "Public Segwit P2SH(P2WPKH)   - " << seg     << endl << endl;
}

