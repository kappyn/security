// autor: kroupkev

#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <climits>
#include <random>
#include <algorithm>
#include <sstream>
#include <string>
#include <byteswap.h>
#include <openssl/evp.h>
#include <bitset>
#include <fstream>
#include <iomanip>
#include <openssl/err.h>

using namespace std;

#define HEADER_SIZE 18
#define BUFFER_SIZE 4096
#define ENCRYPT 1
#define DECRYPT 0

class CBitStream {
private:
	struct STNGHeader {
		uint8_t m_ImageIdLen;
		uint8_t m_CMapType;
		uint8_t m_ImageType;
		uint16_t m_FirstEntryIndex;
		uint16_t m_CMapLen;
		uint8_t m_CMapBitDepth;
		uint16_t m_XO;
		uint16_t m_YO;
		uint16_t m_ImageW;
		uint16_t m_ImageH;
		uint8_t m_Depth;
		uint8_t m_ImageDescriptor;

		void DebugHeader( ) const {
			int fds = 30;
			cout << setfill( ' ' ) << setw( fds ) << "ImageIdLen: ";
			get_b( m_ImageIdLen );
			cout << setfill( ' ' ) << setw( fds ) << "CMapType: ";
			get_b( m_CMapType );
			cout << setfill( ' ' ) << setw( fds ) << "ImageType: ";
			get_b( m_ImageType );
			cout << setfill( ' ' ) << setw( fds ) << "FirstEntryIndex: ";
			get_b( m_FirstEntryIndex );
			cout << setfill( ' ' ) << setw( fds ) << "ColorMapLength: ";
			get_b( m_CMapLen );
			cout << setfill( ' ' ) << setw( fds ) << "ColorMapEntrySize: ";
			get_b( m_CMapBitDepth );
			cout << setfill( ' ' ) << setw( fds ) << "X0: ";
			get_b( m_XO );
			cout << setfill( ' ' ) << setw( fds ) << "Y0: ";
			get_b( m_YO );
			cout << setfill( ' ' ) << setw( fds ) << "W: ";
			get_b( m_ImageW );
			cout << setfill( ' ' ) << setw( fds ) << "H: ";
			get_b( m_ImageH );
			cout << setfill( ' ' ) << setw( fds ) << "PixelDepth: ";
			get_b( m_Depth );
			cout << setfill( ' ' ) << setw( fds ) << "ImageDescriptor: ";
			get_b( m_ImageDescriptor );
		}
	};

	static void bswp( uint16_t & n ) {
		n = ( n >> 8 ) | ( n << 8 );
	}

	static void get_b( uint16_t n ) {
		bitset<16> x( n );
		printf( "%16d %16x: ", n, n );
		cout << x << endl;
	}

	static void get_b( uint8_t n ) {
		bitset<8> x( n );
		printf( "%16d %16x: ", n, n );
		cout << x << endl;
	}

	string m_Type;
	int m_Op;

public:
	ifstream & m_Ifs;
	ofstream & m_Ofs;
	char * m_HeaderData = nullptr;
	bool m_LittleEndian;

	explicit CBitStream( ifstream & input, ofstream & output, const string & mode, char op ) : m_Ifs( input ), m_Ofs( output ) {
		int n = 1;
		m_LittleEndian = ( *( char * ) &n == 1 );
		m_Op = ( op == 'e' ) ? ENCRYPT : DECRYPT;
		m_Type = ( mode == "ecb" ) ? "aes-128-ecb" : "aes-128-cbc";
	}

	~CBitStream( ) {
		delete[] m_HeaderData;
	}

	static string CreateFileName( char mode, const string & cipher, const string & name ) {
		return name.substr( 0, name.find( '.' ) ) + '_' + cipher + '_' + mode + name.substr( name.find_last_of( '.' ) );
	}

	// header manipulation methods
	template<class T>
	int32_t Write( const T & object, uint32_t size ) {
		size_t tmp = m_Ofs.tellp( );
		if ( size == 2 && typeid( T ) == typeid( uint16_t ) ) {
			uint16_t swp = object;
			endianChck( swp );
			m_Ofs.write( reinterpret_cast<const char *>( &swp ), size );
		} else
			m_Ofs.write( reinterpret_cast<const char *>( &object ), size );
		return ( size_t ) m_Ofs.tellp( ) - tmp;
	}

	uint16_t & endianChck( uint16_t & input ) const {
		if ( !m_LittleEndian )
			bswp( input );
		return input;
	}

	template<class T>
	int32_t Read( T & object, uint32_t size ) {
		m_Ifs.read( reinterpret_cast<char *>(&object), size );
		return m_Ifs.gcount( );
	}

	// buffer functions for ciphers
	template<class T>
	int32_t WriteBuffer( const T & obj, uint32_t bytes ) {
		size_t tmp = m_Ofs.tellp( );
		m_Ofs.write( reinterpret_cast<const char *>(&obj), bytes );
		return ( size_t ) m_Ofs.tellp( ) - tmp;
	}

	bool Pipe( uint32_t bytes ) {
		uint8_t buff[ BUFFER_SIZE ];
		while ( bytes > 0 ) {
			if ( !m_Ifs.read( reinterpret_cast<char *>(&buff), min( bytes, ( uint32_t ) sizeof( buff ) ) ) )
				return false;
			if ( !m_Ofs.write( reinterpret_cast<const char *>(&buff), m_Ifs.gcount( ) ) )
				return false;
			bytes -= m_Ifs.gcount( );
		}
		return m_Ifs && m_Ofs;
	}

	bool Run( ) {
		STNGHeader header { };

		// header check
		if ( !ProcessHeader( header ) )
			return false;

		// initialize buffers and keys
		unsigned char key[] = "0123456789abcdef";
		unsigned char iv[] =  "1234567887654321";

		// context
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new( );
		if ( !ctx ) {
			ERR_print_errors_fp( stderr );
			return false;
		}

		// cipher type (cbc, ecb)
		const EVP_CIPHER * type = EVP_get_cipherbyname( m_Type.c_str( ) );
		if ( !type ) {
			ERR_print_errors_fp( stderr );
			return false;
		}

		unsigned char inbuf[BUFFER_SIZE];
		unsigned char outbf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

		// initializes context based on cipher type
		if ( type == EVP_get_cipherbyname( "ecb" ) ) {
			if ( !EVP_CipherInit_ex( ctx, type, nullptr, key, nullptr, m_Op ) ) {
//				ERR_print_errors_fp( stderr );
				return false;
			}
		} else {
			if ( !EVP_CipherInit_ex( ctx, type, nullptr, key, iv, m_Op ) ) {
//				ERR_print_errors_fp( stderr );
				return false;
			}
		}

		// cipher process (block by block)
		int inlen, outlen = 0;
		while ( ( inlen = Read( inbuf, sizeof( inbuf ) ) ) > 0 ) {
			if ( !EVP_CipherUpdate( ctx, outbf, &outlen, inbuf, inlen ) ) {
//				ERR_print_errors_fp( stderr );
				return false;
			}
			if ( outlen != 0 && WriteBuffer( outbf, outlen ) == 0 ) {
				return false;
			}
		}
		if ( !EVP_CipherFinal_ex( ctx, outbf, &outlen ) ) {
//			ERR_print_errors_fp( stderr );
			return false;
		}
		if ( outlen != 0 && WriteBuffer( outbf, outlen ) == 0 ) {
			return false;
		}

		uint32_t fileSize =
				HEADER_SIZE
				+ ( header.m_ImageIdLen + header.m_CMapLen * header.m_Depth / 8 )
				+ ( header.m_ImageW * header.m_ImageH * header.m_Depth );

		// cleanup
		EVP_CIPHER_CTX_free( ctx );
		return fileSize <= ( uint32_t ) m_Ifs.tellg( );
	}

	bool ProcessHeader( STNGHeader & header ) {
		m_HeaderData = new char[HEADER_SIZE];
		m_Ifs.read( m_HeaderData, HEADER_SIZE );
		if ( !m_Ifs ) {
			cout << "Nastal problem pri nacteni hlavicky ze souboru." << endl;
			return false;
		}

		// for header to be completely identical, i copy byte by byte to avoid struct padding
		header.m_ImageIdLen = static_cast<uint8_t>(m_HeaderData[ 0 ]);
		Write( header.m_ImageIdLen, 1 );
		header.m_CMapType = static_cast<uint8_t>(m_HeaderData[ 1 ]);
		Write( header.m_CMapType, 1 );
		header.m_ImageType = static_cast<uint8_t>(m_HeaderData[ 2 ]);
		Write( header.m_ImageType, 1 );
		header.m_FirstEntryIndex = endianChck( *( uint16_t * ) &m_HeaderData[ 3 ] );
		Write( header.m_FirstEntryIndex, 2 );
		header.m_CMapLen = endianChck( *( uint16_t * ) &m_HeaderData[ 5 ] );
		Write( header.m_CMapLen, 2 );
		header.m_CMapBitDepth = static_cast<uint8_t>(m_HeaderData[ 7 ]);
		Write( header.m_CMapBitDepth, 1 );
		header.m_XO = endianChck( *( uint16_t * ) &m_HeaderData[ 8 ] );
		Write( header.m_XO, 2 );
		header.m_YO = endianChck( *( uint16_t * ) &m_HeaderData[ 10 ] );
		Write( header.m_YO, 2 );
		header.m_ImageW = endianChck( *( uint16_t * ) &m_HeaderData[ 12 ] );
		Write( header.m_ImageW, 2 );
		header.m_ImageH = endianChck( *( uint16_t * ) &m_HeaderData[ 14 ] );
		Write( header.m_ImageH, 2 );
		header.m_Depth = static_cast<uint8_t>(m_HeaderData[ 16 ]);
		Write( header.m_Depth, 1 );
		header.m_ImageDescriptor = static_cast<uint8_t>(m_HeaderData[ 17 ]);
		Write( header.m_ImageDescriptor, 1 );

//		header.DebugHeader( );

		if ( !Pipe( header.m_ImageIdLen ) ) {
			cout << "Nastal problem pri nacteni ID z hlavicky." << endl;
			return false;
		}

		if ( !Pipe( header.m_CMapLen * header.m_CMapBitDepth / 8 ) ) {
			cout << "Nastal problem pri nacteni mapy z hlavicky." << endl;
			return false;
		}

		return true;
	}
};

int main( int argc, char * argv[] ) {
	if ( argc != 4 ) {
		fprintf( stderr, "Pouziti: %s [ACTION] [MODE] [FILENAME]\n", argv[ 0 ] );
		return 1;
	}
	if (
			( ( argv[ 1 ][ 0 ] != 'e' ) && ( argv[ 1 ][ 0 ] != 'd' ) ) ||
		 	( strcmp( argv[ 2 ], "ecb" ) != 0 && strcmp( argv[ 2 ], "cbc" ) != 0 )
	) {
		fprintf( stderr, "Neplatny vstup.\n" );
		return 2;
	}

	char ACTION = argv[ 1 ][ 0 ];
	string MODE = argv[ 2 ];
	string FILENAME = argv[ 3 ];

	ifstream ifs( FILENAME, ios::in | ios::binary );
	if ( !ifs )
		return 3;

	string output = CBitStream::CreateFileName( ACTION, MODE, FILENAME );
	ofstream ofs( output, ios::out | ios::binary );
	if ( !ofs )
		return 4;

	// ifs ofs wrapper working as image encryption api
	CBitStream bs { ifs, ofs, MODE, ACTION };
	if ( !bs.Run( ) )
		return 5;

	return 0;
}