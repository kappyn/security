#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <climits>
#include <random>
#include <algorithm>
#include <sstream>
#include <openssl/evp.h>

using namespace std;

string rand_string( size_t len ) {
	// source: https://stackoverflow.com/a/47978023
	string str( "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" );
	random_device rd;
	mt19937 generator( rd( ) );
	shuffle( str.begin( ), str.end( ), generator );
	return str.substr( 0, len - 1 );
}

bool scan_zeros( const unsigned char * hash, unsigned hashLn, unsigned requiredZeros ) {
	unsigned z = 0, end = 0;
	for ( unsigned i = 0 ; i < hashLn ; ++i ) {
		for ( int j = 7 ; j >= 0 ; --j ) {
			if ( ( ( hash[ i ] >> j ) & 1 ) == 0 )
				z++;
			else {
				end = 1;
				break;
			}
		}
		if ( end )
			break;
	}
//	cout << ( ( z < requiredZeros ) ? "Bad hash.\n" : "Good hash.\n" );
	return z >= requiredZeros;
}

void print_instance( const char * text, const unsigned char * hash, unsigned hashLn ) {
	stringstream ss;
	ss << hex << setfill( '0' );
	for ( size_t i = 0 ; strlen( text ) > i ; ++i )
		ss << setw( 2 ) << static_cast<unsigned int>(static_cast<unsigned char>(text[ i ]));
	cout << ss.str( ) << '\n';
	for ( unsigned int j = 0 ; j < hashLn ; j++ )
		printf( "%02x", hash[ j ] );
	cout << endl;
}

int main( int argc, char * argv[] ) {
#define TEXT_LEN 15
	// arg check
	if ( argc != 2 ) {
		fprintf( stderr, "Usage: %s [zero_bits]\n", argv[ 0 ] );
		return 1;
	}

	// arg conversion
	long zero_bits = strtol( argv[ 1 ], nullptr, 10 );
	if ( zero_bits > INT_MAX || zero_bits <= 0 ) {
		fprintf( stderr, "Invalid argument.\n" );
		return 2;
	}

	// for backward compatibility (deprecated)
	OpenSSL_add_all_digests( );
	const EVP_MD * type = EVP_get_digestbyname( "sha384" );
	if ( type == nullptr )
		return 3;

	// infinite loop for hash searching
	int message_processed;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int length;
	while ( true ) {
		// create context for hashing
		EVP_MD_CTX * ctx = EVP_MD_CTX_create( );
		if ( ctx == nullptr )
			return 4;
		auto context_initialized = EVP_DigestInit_ex( ctx, type, nullptr );
		if ( not context_initialized )
			return 5;

		// hashing process
		const char * text;
		text = rand_string( TEXT_LEN ).c_str( );
		message_processed = EVP_DigestUpdate( ctx, text, strlen( text ) );
		if ( not message_processed )
			return 6;
		auto message_hashed = EVP_DigestFinal_ex( ctx, hash, &length );
		if ( not message_hashed )
			return 7;

		// msb bit scanning
		if ( scan_zeros( hash, length, zero_bits ) ) {
			// we've found a fitting hash
			print_instance( text, hash, length );
			EVP_MD_CTX_destroy( ctx );
			break;
		}

		// context cleanup
		EVP_MD_CTX_destroy( ctx );
	}
	return 0;
}