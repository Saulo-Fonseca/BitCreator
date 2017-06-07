#!/usr/bin/perl
# Author: Saulo Fonseca
# Description: Generate Bitcoin Private / Public Addresses
use Digest::SHA qw(sha256_hex);
use warnings;
use strict;
use bigint;

# Create keypair in hex
sub genKey
{
	my $hex  = [`openssl ecparam -name secp256k1 -genkey | openssl ec -text -noout 2>/dev/null`];
	$_ =~ s/^\s+|\s+$|:|\n//g foreach (@$hex);
	my $hexPriv = $hex->[2].$hex->[3].$hex->[4];
	my $hexPub  = $hex->[6].$hex->[7].$hex->[8].$hex->[9].$hex->[10];
	return (uc $hexPriv, uc $hexPub);
}

# Convert to Mainnet address and add checksum
sub mainnetChecksum
{
	my $mainnet  = shift; # 0x80 for private key and 0x00 for public key
	my $key      = shift; # Hex with 32 bytes for private key and 20 for ripemd160 ofpublic key
	my $length   = shift; # Inform if 32 bytes (64 chars) or 20 bytes (40 chars)
	my $compress = shift; # If defined, generate the compressed form for private key
	   $key      = substr($key,-$length); # Take only last $length chars
	   $mainnet  = $mainnet.$key;
	   $mainnet .= "01" if ($compress);
	my $sha256   = sha256_hex(pack 'H*',(sha256_hex(pack 'H*',$mainnet)));
	my $checksum = substr($sha256,0,8);
	my $newKey   = $mainnet.$checksum;
	return uc $newKey;
}

# Encode to base58 using Base58Check encoding 
sub encodeBase58Check
{
	# Define vars
	my $hex = shift;
	my $base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	# Find multiple rest of division by 58
	my $dec = hex($hex);
	my $output =  "";
	while ($dec>0)
	{
		my $remainder = $dec % 58;
		$dec = ($dec-$remainder)/58;
		$output = substr($base58,$remainder,1).$output;
		return "ThisWasNaN" if ($dec eq "NaN");
	}

	# Replace all leading zeros with 1
	while (substr($hex,0,2) eq "00")
	{
		$output = substr($base58,0,1).$output;
		$hex = substr($hex,2);
	}
	return $output;
}

# Create Private Key Wallet Inport Format (WIF)
sub wif
{
	my $hex = shift;
	my $compress = (defined shift) ? 1 : 0;
	my $hexCheck = mainnetChecksum("80",$hex,64,$compress);
	return encodeBase58Check($hexCheck);
}

# Create Ripemd-160
sub ripemd160
{
	my $hex = shift;
	my $output = `echo $hex | xxd -r -p | openssl rmd160`;
	chomp($output);
	return uc $output;
}

# Create bitcon Binary Address
sub binaryAddr
{
	# Empty argument generate key for 1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E
	my $hex      = shift;
	my $sha256   = sha256_hex(pack 'H*',$hex);
	my $hexCheck = mainnetChecksum("00",ripemd160($sha256),40,0);
	return encodeBase58Check($hexCheck);
}

# Split X and Y values from public key
sub splitXY
{
	my $key = shift;
	my $x   = substr($key,2,64);
	my $y   = substr($key,66);
	my $dec = hex($y);
	return "02".$x if ($dec % 2 eq 0);
	return "03".$x;
}

# Generate private and prublic keys
my ($hexPriv,$hexPub) = genKey();
my $priv   = wif($hexPriv);
my $privC  = wif($hexPriv,1);               # Compressed
my $pub    = binaryAddr($hexPub);
my $pubC   = binaryAddr(splitXY($hexPub));  # Compressed

# Print private / public key in normal and compressed forms
print "$priv\n";
print "$pub\n";	
print "$privC\n";
print "$pubC\n";

