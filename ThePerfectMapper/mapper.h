#pragma once


//
// inclusions 
//
#include <map>
#include <vector>
#include <format>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#include <winhttp.h>
#include <filesystem>
#include <unordered_map>
#include ".\intel_drv\intel_driver.hpp"
#include ".\intel_drv\portable_executable.hpp"
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")
#define PerfectMapper_Magic "PM"
#undef min


/* PM export descriptors */
typedef struct _eat_desc
{
	const char* name;
	WORD ordinal;
	DWORD rva;
	const char* forwarder;
}eat_desc, *peat_desc;
typedef struct _myeat
{
	std::vector<std::string> components;
	eat_desc desc;
}myeat, *pmyeat;


/* PDB Related */
#pragma pack(push, 1)

/* PDB + DBI */
struct MsfSuperBlock
{
	char     magic[32];        // "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0"
	uint32_t blockSize;        // typical: 0x400 or 0x200 or 0x1000
	uint32_t freeBlockMapBlock;
	uint32_t numBlocks;
	uint32_t numDirectoryBytes;
	uint32_t reserved;         // <- you were missing this
	uint32_t blockMapAddr;     // block index of *directory block index array*
};
struct DBIHeader {
	int32_t  VersionSignature;
	uint32_t VersionHeader;
	uint32_t Age;
	uint16_t GlobalStreamIndex;
	uint16_t BuildNumber;
	uint16_t PublicStreamIndex;    // <-- we want this
	uint16_t PdbDllVersion;
	uint16_t SymRecordStream;
	uint16_t PdbDllRbld;
	int32_t  ModInfoSize;
	int32_t  SectionContributionSize;
	int32_t  SectionMapSize;
	int32_t  SourceInfoSize;
	int32_t  TypeServerSize;
	uint32_t MFCTypeServerIndex;
	int32_t  OptionalDbgHeaderSize;
	int32_t  ECSubstreamSize;
	uint16_t Flags;
	uint16_t Machine;
	uint32_t Padding;
};
struct PdbStreamHeader7 {
	uint32_t version;    // some known magic-ish number like 20000404 etc
	uint32_t signature;  // random-ish
	uint32_t age;        // small integer
	/* we don't need the others rn */
};

/* SYM + wrappers */
typedef struct _pdb_sym_desc
{
	uint16_t size;		/* desc length */
	uint16_t type;		/* desc type */
	uint32_t flags;
	uint32_t off;
	uint16_t seg;
	const char name[];
}pdb_sym_desc, * ppdb_sym_desc;
struct my_sym_loc {
	uint16_t seg;
	uint32_t off;
};

/* TPI + UDT + Fields */
struct TpiHeader {
	uint32_t version;
	uint32_t headerSize;
	uint32_t typeIndexBegin;   // first valid type index (usually 0x1000)
	uint32_t typeIndexEnd;     // one past last
	uint32_t typeRecordBytes;  // size of all type records that follow
	uint16_t hashStreamIndex;
	uint16_t hashAuxStreamIndex;
	uint32_t hashKeySize;
	uint32_t numHashBuckets;
};
struct pm_tpi_leaf_desc
{
	uint16_t len;
	uint16_t leaf;
};
typedef struct _udt_desc
{
	uint16_t lf_type;        // LF_STRUCTURE / LF_CLASS / LF_UNION
	uint16_t member_count;
	uint16_t props;
	uint32_t field_list_ti;
	uint32_t derived_ti;
	uint32_t vshape_ti;
}udt_desc, *pudt_desc;
enum : uint16_t {
	LF_CLASS = 0x1504,
	LF_STRUCTURE = 0x1505,
	LF_UNION = 0x1506,
	LF_FIELDLIST = 0x1203,
	LF_MEMBER = 0x150d,
};

#pragma pack(pop)


//
// This class will be used to parse the 
// needed PDB files instead of using normal IAT
// this makes it more efficient and useful than normal
// mappers that only resolve exported symbols
//
class PPDBParser
{
public:
	
	/* constructor */
	PPDBParser( std::string module_name, std::wstring _cache_dir = L".\\Cached\\" )
	{
		/* saving the params */
		this->mod_name = module_name;
		this->cache_dir = _cache_dir;

		/* intializing */
		this->init( module_name );
		return;
	}

	/* initializer */
	bool init( std::string module_name )
	{
		/* vars */
		bool _check = false;

		/* finding the file and getting the final PDB url + the hypotethical file id */
		for ( const auto& path : this->lookup_paths )
		{
			_check = this->get_pdb_url( path + module_name );
			if ( _check ) break;
		}
		if ( !_check ) return false; /* failed to find and create a pdb for the target! */


		/* checking if the file is present ( if it is we use it instead of fetching the pdb from the servers ) */
		std::wstring final_path_in_cache = this->cache_dir + this->file_id;
		if ( !std::filesystem::exists( final_path_in_cache ) )
		{
			/* getting the PDB content */
			if ( !this->fetch_pdb( this->pdb_url ) ) return false;

			/* saving the file into the cache dir ( only if the file does not already exist ) */
			if ( !this->save_pdb_into_cache( final_path_in_cache ) ) return false;
		}
		/* in case the file is in cache we get it from there */
		else { if ( !this->read_pdb_from_cache( final_path_in_cache ) ) return false; }
		

		/* actually parsing the PBD */
		if ( !this->parse( ) ) return false;


		/* marking as intiialized and returning */
		this->initialized = true;
		return true;
	}

	/* this will find the target file ( as long as in a lookup path ) and format the url for the pdb */
	bool get_pdb_url( std::string mod_path )
	{
		/* symbol path: SRV*<cache>*<msdl> + getting the curr proc */
		HANDLE proc = GetCurrentProcess( );
		std::string syms = "SRV*C:\\Symbols\\*https://msdl.microsoft.com/download/symbols";

		/* intializing the symbol handler for the current process */
		if ( !SymInitialize( proc, syms.c_str( ), FALSE ) ) return false;

		/* setting the needed options */
		SymSetOptions( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );

		/* mod_path is assumed to be a full path here */
		SYMSRV_INDEX_INFO info{};
		info.sizeofstruct = sizeof( info );
		if ( !SymSrvGetFileIndexInfo( mod_path.c_str( ), &info, 0 ) ) {
			SymCleanup( proc );
			return false;
		}

		/* composing the final URL for the symbols */
		std::wstring temp_url = L"http://msdl.microsoft.com/download/symbols/";
		std::wstring temp_file_id = L"";
		std::wstring wstr_pdbname = std::wstring( info.pdbfile, info.pdbfile + std::strlen( info.pdbfile ) );
		temp_url.append( wstr_pdbname +  L"/" ); /* ex: ntkrnlmp.pdb */

		/* building the file id */
		temp_file_id.append( std::format( L"{:08X}", info.guid.Data1 ) );
		temp_file_id.append( std::format( L"{:04X}", info.guid.Data2 ) );
		temp_file_id.append( std::format( L"{:04X}", info.guid.Data3 ) );
		for ( int i = 0; i < 8; i++ ) { temp_file_id.append( std::format( L"{:02X}", info.guid.Data4[i] ) ); }
		
		/* fixing the URL */
		temp_url.append( temp_file_id );
		temp_url.append( std::to_wstring( info.age ) + L"/" );
		temp_url.append( wstr_pdbname );
		this->pdb_url = temp_url;
	
		/* fixing the file ID */
		temp_file_id.append( L"." + std::to_wstring( info.age ) + L".pdb" );
		this->file_id = temp_file_id;

		/* cleanup */
		SymCleanup( proc );
		return true;
	}

	/* fetch pdb ( --> downloading the PDB content from the URL ) */
	bool fetch_pdb( std::wstring url )
	{
		/* vars */
		URL_COMPONENTS uc{};
		wchar_t host[256];
		wchar_t path[2048];

		/* initializing the needed sutrcture */
		memset( &uc, 0, sizeof( uc ) );
		uc.dwStructSize = sizeof( uc );
		uc.lpszHostName = host;
		uc.dwHostNameLength = _countof( host );
		uc.lpszUrlPath = path;
		uc.dwUrlPathLength = _countof( path );

		/* "cracking" the URL */
		if ( !WinHttpCrackUrl( url.c_str( ), 0, 0, &uc ) ) return false;

		/* creating the session */
		bool isHttps = ( uc.nScheme == INTERNET_SCHEME_HTTPS );
		HINTERNET hSession = WinHttpOpen( L"JesusIsKing/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
		if ( !hSession ) return false;

		/* connecting */
		HINTERNET hConnect = WinHttpConnect( hSession, host, uc.nPort, 0 );
		if ( !hConnect ) 
		{
			WinHttpCloseHandle( hSession );
			return false;
		}

		/* opening the request */
		DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
		HINTERNET hRequest = WinHttpOpenRequest( hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags );
		if ( !hRequest ) 
		{
			WinHttpCloseHandle( hConnect );
			WinHttpCloseHandle( hSession );
			return false;
		}

		/* sending the request */
		BOOL ok = WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );
		if ( !ok ) 
		{
			WinHttpCloseHandle( hRequest );
			WinHttpCloseHandle( hConnect );
			WinHttpCloseHandle( hSession );
			return false;
		}

		/* receiving the response */
		ok = WinHttpReceiveResponse( hRequest, nullptr );
		if ( !ok ) 
		{
			WinHttpCloseHandle( hRequest );
			WinHttpCloseHandle( hConnect );
			WinHttpCloseHandle( hSession );
			return false;
		}
		
		/* read the body */
		for ( ;; ) 
		{
			DWORD avail = 0;
			if ( !WinHttpQueryDataAvailable( hRequest, &avail ) || avail == 0 )
				break;

			DWORD read = 0;
			std::vector<uint8_t> buf( avail );
			if ( !WinHttpReadData( hRequest, buf.data( ), avail, &read ) || read == 0 )
				break;

			this->pdb.insert( this->pdb.end( ), buf.begin( ), buf.begin( ) + read );
		}


		/* cleanup */
		WinHttpCloseHandle( hRequest );
		WinHttpCloseHandle( hConnect );
		WinHttpCloseHandle( hSession );
		return true;
	}

	/* this function will be used by the parser to get a specific stream from the pdb */
	std::vector<uint8_t> get_stream( uint32_t idx )
	{
		/* vars */
		size_t dst = 0;
		std::vector<uint8_t> output;
		uint32_t size = this->ssizes[idx];
		if ( size == 0xFFFFFFFF || !size ) return output;
	
		/* resizing the vector */
		output.resize( size );
		
		/* getting the blocks for the stream */
		for ( uint32_t block : this->sblocks[idx] )
		{
			if ( !this->sb || block >= this->sb->numBlocks ) break;
			const uint8_t* src = this->pdb.data( ) + ( block * this->block_size );
			size_t to_copy = std::min<size_t>( block_size, size - dst );
			memcpy( output.data( ) + dst, src, to_copy );
			dst += to_copy;
		}

		/* returning the stream */
		return output;
	}

	/* this function will be used to locate a target symbol in the PDB and return its RVA */
	std::optional<my_sym_loc> find_symbol( const std::string& fn_name )
	{
		/* basic checks */
		if ( !this->parsed || this->dbi.size( ) <= 0 ) return std::nullopt;

		/* vars */
		uintptr_t* cur = ( uintptr_t* )this->sym.data( );
		uintptr_t* end = ( uintptr_t* )( ( uintptr_t )this->sym.data( ) + this->sym.size( ) );
		bool disp = false;
		int iterated = 0;

		/* iterating over each symbol */
		while ( cur + sizeof( pdb_sym_desc ) <= end )
		{
			ppdb_sym_desc desc = ( ppdb_sym_desc )cur;
			if ( !desc->size ) break;

			/* we're interested */
			if ( desc->type == 0x110E )
			{
				if ( std::string( desc->name ) == fn_name )
					return my_sym_loc{ desc->seg, desc->off };
			}

			/* next aligned at 4-bytes */
			cur = ( uintptr_t* )( ( ( uintptr_t )cur + desc->size ) + 3u & ~uintptr_t( 3 ) );
		}

		/* failed */
		return std::nullopt;
	}

	/* this function will be used to locate a target structure and retrieve a field offset ( ex: _EPROCESS.DirectoryTableBase )*/
	std::optional<uint32_t> find_struct_field( const std::string& struct_name, const std::string& field_name )
	{
		/* basic checks */
		if ( !this->parsed || this->tpi.size( ) <= 0 ) return std::nullopt;

		/* vars */
		const uintptr_t		tpi_base			= ( uintptr_t )this->tpi.data( );
		const uintptr_t		tpi_end				= tpi_base + this->tpi.size( );
		const TpiHeader*	tpi_hdr				= ( TpiHeader* )tpi_base;
		const uintptr_t		type_records		= tpi_base + tpi_hdr->headerSize;
		const uintptr_t		type_records_end	= type_records + tpi_hdr->typeRecordBytes;

		/* building the type index ( if not already built ) */
		if ( this->type_index.empty( ) )
		{
			/* inner vars */
			uintptr_t cur = type_records;
			uint32_t ti = tpi_hdr->typeIndexBegin;
			uint32_t ti_end = tpi_hdr->typeIndexEnd;

			/* resizing the vector */
			this->type_index.resize( ti_end - ti, nullptr );

			/* iterating over each leaf */
			while ( cur + 4 <= type_records_end && ti < ti_end )
			{
				pm_tpi_leaf_desc*	leaf_desc		= ( pm_tpi_leaf_desc* )cur;
				const uint8_t*		rec_data		= ( uint8_t* )( cur + 2 );
				const uint8_t*		rec_data_end	= ( uint8_t* )( cur + 2 + leaf_desc->len );
				if ( ( uintptr_t )rec_data_end > type_records_end ) break;

				/* inserting the leaf pointer into the map */
				this->type_index[ti - tpi_hdr->typeIndexBegin] = rec_data;

				const uint8_t* next = ( uint8_t* )( cur + 2 + leaf_desc->len );
				cur = ( reinterpret_cast< uintptr_t >( next ) + 3 ) & ~uintptr_t( 3 );
				++ti;
			}
		}
		
		/* iterating the type index */
		for ( const auto& entry : this->type_index )
		{
			/* inner vars */
			pudt_desc desc = ( pudt_desc )entry; /* must be one of the followig: struct, union, class */
			if ( desc->lf_type != LF_STRUCTURE && desc->lf_type != LF_CLASS && desc->lf_type != LF_UNION ) continue;

			// one pointer, advanced by the helpers:
			const uint8_t* ptr = ( uint8_t* )entry + sizeof( udt_desc );
			uint32_t size_bytes = this->pm_read_numeric( ptr );
			if ( !size_bytes ) continue; /* invalid or duplicate */

			/* getting the name */
			std::string name = this->pm_read_string( ptr );
			if ( name == struct_name )
			{
				int offset = this->get_struct_off_from_fieldname( desc->field_list_ti, field_name );
				if ( offset != -1 ) return offset;
			}
		}

		return std::nullopt;
	}

	/* initialization check */
	__forceinline bool is_initialized( ) { return this->initialized; }

	/* getting the pdb url */
	__forceinline std::wstring get_pdb_url( ) { return this->pdb_url; }

	/* getting the file id */
	__forceinline std::wstring get_file_id( ) { return this->file_id; }

	/* dynamically add path */
	__forceinline void add_lookup_path( std::string _path ) 
	{ 
		this->lookup_paths.push_back( _path ); 
		return;
	}

protected:

	/* this will parse the pdb to get all the entries we need */
	bool parse( )
	{
		/* getting the SuperBlock + little magic check */
		this->sb = ( MsfSuperBlock* )this->pdb.data( );
		if ( std::string( this->sb->magic ).find( "Microsoft" ) == std::string::npos ) return false;

		/* vars */
		const uint8_t* pdb_base = pdb.data( );
		this->block_size = this->sb->blockSize;
		uint32_t		dir_bytes = this->sb->numDirectoryBytes;
		uint32_t		num_dir_blks = ( dir_bytes + this->block_size - 1 ) / this->block_size;
		const uint32_t* dir_block_idxes = reinterpret_cast< uint32_t* >( ( uintptr_t )pdb_base + ( this->sb->blockMapAddr * this->block_size ) );

		/* we reassemble the directory into a single buffer */
		this->pdb_dir.resize( dir_bytes );	/* size of the directory */
		for ( uint32_t i = 0, dst_off = 0; i < num_dir_blks; ++i )
		{
			uint32_t blk = dir_block_idxes[i];
			if ( ( uint64_t )blk * this->block_size >= this->pdb.size( ) ) break;

			const uint8_t* src = pdb_base + blk * this->block_size;

			size_t toCopy = std::min<size_t>( this->block_size, dir_bytes - dst_off );
			memcpy( this->pdb_dir.data( ) + dst_off, src, toCopy );
			dst_off += ( uint32_t )toCopy;
		}

		/* getting the directory attributes */
		const uint8_t* dir_base = this->pdb_dir.data( );
		const uint8_t* dir_end = dir_base + this->pdb_dir.size( );
		uint32_t n_of_streams = *reinterpret_cast< uint32_t* >( ( uintptr_t )dir_base );
		dir_base += sizeof( uint32_t );

		/* getting the stream sizes */
		this->ssizes.resize( n_of_streams );
		memcpy( this->ssizes.data( ), dir_base, n_of_streams * sizeof( uint32_t ) );
		dir_base += n_of_streams * sizeof( uint32_t );

		/* getting the stream blocks */
		this->sblocks.resize( n_of_streams );
		for ( uint32_t i = 0; i < n_of_streams; i++ )
		{
			/* getting the size of the block */
			uint32_t size = this->ssizes[i];

			/* unused */
			if ( size == 0xFFFFFFFF ) { this->sblocks[i] = {}; continue; }

			/* resizeing a specific block in the array */
			uint32_t blocks_for_stream = ( size + this->block_size - 1 ) / this->block_size;
			this->sblocks[i].resize( blocks_for_stream );

			/* checking if there is any problem */
			if ( dir_base + blocks_for_stream * sizeof( uint32_t ) > dir_end ) break;

			/* copying the contents */
			memcpy( this->sblocks[i].data( ), dir_base, blocks_for_stream * sizeof( uint32_t ) );
			dir_base += blocks_for_stream * sizeof( uint32_t );
		}

		/* getting the stream we're interested in */
		this->dbi = this->get_stream( 3 );
		if ( this->dbi.size( ) < sizeof( DBIHeader ) ) return false;

		/* getting the dbi header and the public stream idx */
		this->dbi_hdr = reinterpret_cast< DBIHeader* >( this->dbi.data( ) );
		this->pubs_idx = dbi_hdr->PublicStreamIndex;
		this->sym_idx = dbi_hdr->SymRecordStream;
		if ( this->pubs_idx >= this->ssizes.size( ) ) return false;
		if ( this->sym_idx >= this->ssizes.size( ) ) return false;

		/* getting the symbols directory */
		this->sym = this->get_stream( this->sym_idx );
		if ( this->sym.empty( ) ) return false;

		/* getting the TPI stream */
		this->tpi = this->get_stream( 2 );
		if ( this->tpi.empty( ) ) return false;

		/* marking this PDB as parsed */
		this->parsed = true;
		return true;
	}

	/* saves the current stored PDB into the cache path ( this will make the process faster ) */
	bool save_pdb_into_cache( std::wstring _path )
	{
		/* checking if the file already exists */
		if ( std::filesystem::exists( _path ) ) return true;

		/* if we're here it means the file does not exists so we have to create it */
		std::filesystem::create_directories( this->cache_dir );

		/* opening the file */
		std::fstream file( _path, std::ios::out | std::ios::binary | std::ios::trunc );
		if ( !file.is_open( ) ) return false; /* invalid path or could not open the files*/

		/* writing the file */
		file.write( ( const char* )this->pdb.data( ), static_cast< std::streamsize >( this->pdb.size( ) ) );

		/* closing the file and returning */
		file.close( );
		return true;
	}

	/* read pdb from cache */
	bool read_pdb_from_cache( std::wstring _path )
	{
		/* checking if the file exists */
		if ( !std::filesystem::exists( _path ) ) return false;

		/* opening the file */
		std::fstream file( _path, std::ios::in | std::ios::binary );
		if ( !file.is_open( ) ) return false;

		/* getting the file size */
		file.seekg( 0, std::ios::end );
		std::streamsize _size = file.tellg( );
		if ( _size <= 0 ) return false;
		file.seekg( 0, std::ios::beg );

		/* reading the file */
		this->pdb.resize( static_cast< size_t >( _size ) );
		if ( _size && !file.read( reinterpret_cast< char* >( this->pdb.data( ) ), _size ) ) return false;
		return true;
	}

	/* this will advance the given pointer to get the base address of the name string */
	static uint32_t pm_read_numeric( const uint8_t*& p )
	{
		uint16_t v = *reinterpret_cast< const uint16_t* >( p );
		p += 2;

		// Simple case: small value encoded directly
		if ( v < 0x8000 ) return v;

		// Extended encodings
		switch ( v )
		{
		case 0x8000: // LF_CHAR
		{
			int8_t x = *reinterpret_cast< const int8_t* >( p );
			p += 1;
			return static_cast< uint8_t >( x );
		}
		case 0x8001: // LF_SHORT
		{
			int16_t x = *reinterpret_cast< const int16_t* >( p );
			p += 2;
			return static_cast< uint16_t >( x );
		}
		case 0x8002: // LF_USHORT
		{
			uint16_t x = *reinterpret_cast< const uint16_t* >( p );
			p += 2;
			return x;
		}
		case 0x8003: // LF_LONG
		{
			int32_t x = *reinterpret_cast< const int32_t* >( p );
			p += 4;
			return static_cast< uint32_t >( x );
		}
		case 0x8004: // LF_ULONG
		{
			uint32_t x = *reinterpret_cast< const uint32_t* >( p );
			p += 4;
			return x;
		}
		default:
			return 0;
		}
	}

	/* this returns a string given the str base of the type in the PDB */
	static std::string pm_read_string( const uint8_t*& p )
	{
		const char* s = reinterpret_cast< const char* >( p );
		size_t len = std::strlen( s );
		std::string out( s, len );
		p += len + 1;
		return out;
	}

	/* this will get the offset of a members */
	int get_struct_off_from_fieldname( uint32_t fieldlist_ti, const std::string& field_name )
	{
		/* vars */
		const uintptr_t tpi_base = ( uintptr_t )this->tpi.data( );
		const TpiHeader* tpi_hdr = ( const TpiHeader* )tpi_base;

		/* getting the needed vars */
		uint32_t ti_begin = tpi_hdr->typeIndexBegin;		if ( fieldlist_ti < ti_begin ) return -1;
		size_t idx = fieldlist_ti - ti_begin;				if ( idx >= this->type_index.size( ) ) return -1;
		uint8_t* entry = ( uint8_t* )this->type_index[idx];	if ( !entry ) return -1;

		/* getting the start of the block, the length and the end */
		uintptr_t	ptr = (uintptr_t)entry;	/* length is at entry - 2 */
		uint16_t	len = *( uint16_t* )( ( uintptr_t )entry - 2 ); 
		uintptr_t	end = ptr + len;

		/* checking if it's a LF_FIELDLIST */
		if ( *( uint16_t* )ptr != LF_FIELDLIST ) return -1;
		
		/* now we have to interate for each field in the structure */
		while ( ptr < end )
		{
			/* checking if there's still an entry that we can parse */
			if ( ptr + 2 > end ) break;
			
			/* getting the field */
			uint16_t field_type = *( uint16_t* )ptr; ptr += 2;
			if ( field_type != LF_MEMBER ) continue;	/* only interested in members */

			/* attribute is at +2 [ not needed ] */ ptr += 2;
			/* ti type is at +4   [ not needed ] */ ptr += 4;

			/* from the current ptr pointer we get the field name */
			const uint8_t*	_str_ptr		= ( uint8_t* )( ptr );
			uint32_t		offset			= this->pm_read_numeric( _str_ptr );  // advances p
			std::string		curr_field_name	= this->pm_read_string( _str_ptr ); // advances p

			/* checking if it matches the target */
			if ( curr_field_name != field_name ) continue;
			return offset; /* returning the offset within the target struct */
		}

		/* failed */
		return -1;
	}

private:

	/* attributes */
	bool initialized			= false;
	std::string mod_name		= "";
	std::wstring cache_dir		= L"";
	std::wstring pdb_url		= L"";
	std::wstring file_id		= L"";
	std::vector<uint8_t> pdb	= { };

	/* PDB related */
	bool parsed				= false;
	MsfSuperBlock* sb;
	uint32_t block_size		= 0;
	uint32_t pubs_idx		= 0;
	uint32_t sym_idx		= 0;
	DBIHeader* dbi_hdr		= 0;
	std::vector<BYTE> dbi;
	std::vector<BYTE> sym;
	std::vector<BYTE> tpi;
	std::vector<const uint8_t*> type_index;
	std::vector<uint32_t> ssizes;
	std::vector<std::vector<uint32_t>> sblocks;
	std::vector<uint8_t> pdb_dir;

	/* lookup paths */
	std::vector<std::string> lookup_paths = { "C:\\Windows\\System32\\", "C:\\Windows\\System32\\drivers\\" };

};


//
// This class will be used to map our driver
// but it will also be able to resolve PDB references
// ( PDB Parsing is ON by default )
// 
// Credits: KDMapper by TheCruz
// ( https://github.com/TheCruZ/kdmapper ) 
//
class PMapper
{
public:

	/* bytes constructor */
	PMapper( std::vector<BYTE> _drv_bytes )
	{
		/* loading the intel driver */
		intel_driver::Load( );

		drv_bytes = _drv_bytes;
		return;
	}

	/* file constructor */
	PMapper( std::string path )
	{
		/* loading the intel driver */
		intel_driver::Load( );

		/* opening the target file */
		std::ifstream target_file( path, std::ios::binary );
		if ( !target_file ) throw std::runtime_error( "Could not open the target file!" );

		/* getting the size of the file */
		target_file.seekg( 0, std::ios::end );
		const std::streamsize _size = target_file.tellg( );
		if ( _size < 0 ) throw std::runtime_error( "Could not get the file size!" );
		target_file.seekg( 0, std::ios::beg );

		/* getting the content of the file */
		this->drv_bytes.reserve( static_cast< size_t >( _size ) );
		if ( _size && !target_file.read( reinterpret_cast< char* >( this->drv_bytes.data( ) ), _size ) ) throw std::runtime_error( "read failed" );
		return;
	}


	/* from kdmapper */
	void reloc_img_by_delta( portable_executable::vec_relocs relocs, const ULONG64 delta ) {
		for ( const auto& current_reloc : relocs ) {
			for ( auto i = 0u; i < current_reloc.count; ++i ) {
				const uint16_t type = current_reloc.item[i] >> 12;
				const uint16_t offset = current_reloc.item[i] & 0xFFF;

				if ( type == IMAGE_REL_BASED_DIR64 )
					*reinterpret_cast< ULONG64* >( current_reloc.address + offset ) += delta;
			}
		}
	}


	/* Fix cookie by @Jerem584 [ from kdmapper ] */
	bool fix_sec_cookie( void* local_image, ULONG64 kernel_image_base )
	{
		auto headers = portable_executable::GetNtHeaders( local_image );
		if ( !headers )
			return false;

		auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
		if ( !load_config_directory )
		{
			kdmLog( L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl );
			return true;
		}

		auto load_config_struct = ( PIMAGE_LOAD_CONFIG_DIRECTORY )( ( uintptr_t )local_image + load_config_directory );
		auto stack_cookie = load_config_struct->SecurityCookie;
		if ( !stack_cookie )
		{
			kdmLog( L"[+] StackCookie not defined, fix cookie skipped" << std::endl );
			return true; // as I said, it is not an error and we should allow that behavior
		}

		stack_cookie = stack_cookie - ( uintptr_t )kernel_image_base + ( uintptr_t )local_image; //since our local image is already relocated the base returned will be kernel address

		if ( *( uintptr_t* )( stack_cookie ) != 0x2B992DDFA232 ) {
			kdmLog( L"[-] StackCookie already fixed!? this probably wrong" << std::endl );
			return false;
		}

		kdmLog( L"[+] Fixing stack cookie" << std::endl );

		auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId( ) ^ GetCurrentThreadId( ); // here we don't really care about the value of stack cookie, it will still works and produce nice result
		if ( new_cookie == 0x2B992DDFA232 )
			new_cookie = 0x2B992DDFA233;

		*( uintptr_t* )( stack_cookie ) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
		return true;
	}


	/* from kdmapper */
	bool res_imports( portable_executable::vec_imports imports ) {
		for ( const auto& current_import : imports ) 
		{
			ULONG64 Module = kdmUtils::GetKernelModuleAddress( current_import.module_name );
			if ( !Module ) { return false; }

			for ( auto& current_function_data : current_import.function_datas ) 
			{
				ULONG64 function_address = intel_driver::GetKernelModuleExport( Module, current_function_data.name );

				if ( !function_address ) 
				{
					//Lets try with ntoskrnl
					if ( Module != intel_driver::ntoskrnlAddr ) 
					{
						function_address = intel_driver::GetKernelModuleExport( intel_driver::ntoskrnlAddr, current_function_data.name );
						if ( !function_address ) { return false; }
					}
				}

				*current_function_data.address = function_address;
			}
		}

		return true;
	}


	/* split by character */
	std::vector<std::string> split( const std::string& str, char discriminator = '#' )
	{
		std::vector<std::string> out;
		std::string::size_type start = 0, pos;

		while ( true )
		{
			pos = str.find( discriminator, start );
			if ( pos == std::string::npos )
			{
				out.emplace_back( str.substr( start ) ); 
				break;
			}

			out.emplace_back( str.substr( start, pos - start ) );
			start = pos + 1;
		}

		return out;
	}


	/* this will handle PerfectMapper special cases */
	bool pm_special_eat_handler( std::string special_type, void* local_base, myeat entry )
	{
		/* ------------ No parser needed ------------ */

		/* [ SPECIAL ] presence check */
		if ( special_type.find( "check" ) != std::string::npos )
		{
			*( char* )( ( uintptr_t )local_base + entry.desc.rva ) = 1;
			return true;
		}

		/* ------------ parser needed ------------ */

		std::string target_module = entry.components[4];
		PPDBParser* parser = nullptr;

		/* parser is already present for the target module otherwise we initialize it */
		auto parser_lookup = this->active_parsers.find( target_module );
		if ( parser_lookup != this->active_parsers.end( ) ) { parser = &parser_lookup->second; }
		else { parser = new PPDBParser( target_module ); }
		
		/* checking if the target parser has been intialized correctly */
		if ( !parser->is_initialized( ) ) return false;

		/* [ SPECIAL ] struct offset resolver */
		if ( special_type.find( "offset" ) != std::string::npos )
		{
			/* we need the structure name and the field name for the lookup */
			std::string struct_name = entry.components[5];
			std::string field_name = entry.components[6];

			/* looking up the struct + field --> offset */
			auto opt_offset = parser->find_struct_field( struct_name, field_name );
			if ( !opt_offset ) return false;

			/* setting the actual offset */
			*( uintptr_t* )( ( uintptr_t )local_base + entry.desc.rva ) = *opt_offset;
			return true;
		}

		return false;
	}


	/* resolving the EAT as if it was IAT ( + private symbols with PDB ) */
	bool pm_eat_handler( void* local_base, myeat entry, bool is_special )
	{
		/* vars */
		std::string special_type = "";

		/* if it's special we get the special type */
		if ( is_special )
		{
			for ( const auto& comp : entry.components )
			{
				if ( comp.find( '@' ) != std::string::npos )
				{
					special_type = comp;
					break;
				}
			}
		}
		if ( is_special && special_type.length( ) <= 1 ) return false;

		/* if it's special we forward it to the special handler and then return the value */
		if ( is_special ) return this->pm_special_eat_handler( special_type, local_base, entry );

		/* if it's not special then... */
		std::string target_module = entry.components[3];
		std::string symbol_name = entry.components[4];
		PPDBParser* parser = nullptr;

		/* parser is already present for the target module otherwise we initialize it */
		auto parser_lookup = this->active_parsers.find( target_module );
		if ( parser_lookup != this->active_parsers.end( ) ) { parser = &parser_lookup->second; }
		else { parser = new PPDBParser( target_module ); }

		/* checking if the target parser has been intialized correctly */
		if ( !parser->is_initialized( ) ) return false;

		/* looking for the symbol in the pdb */
		auto opt_sym = parser->find_symbol( symbol_name );
		if ( !opt_sym ) return false;

		/* getting the symbol location in memory */
		uintptr_t va = this->to_va( target_module, opt_sym->seg, opt_sym->off );
		if ( !va ) return false;

		/* setting the actual address and returning true */
		*( uintptr_t* )( ( uintptr_t )local_base + entry.desc.rva ) = va;
		return true;
	}


	/* ThePerfectMapper [ Turning Specific EAT pointers into IAT through PDB parsing ] */
	bool turn_eat_into_iat( void* local_image )
	{
		if ( !local_image ) return false;

		/* NT headers */
		const auto* nt = portable_executable::GetNtHeaders( local_image );
		if ( !nt ) return false;

		auto* base = static_cast< uint8_t* >( local_image );

		/* Export data directory */
		const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if ( dd.VirtualAddress == 0 || dd.Size < sizeof( IMAGE_EXPORT_DIRECTORY ) ) return true; /* no exports* /

		/* Export directory */
		const auto* dir = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( base + dd.VirtualAddress );
		const DWORD dirRva = dd.VirtualAddress;
		const DWORD dirSize = dd.Size;

		/* Tables */
		const DWORD* funcs = reinterpret_cast< const DWORD* >( base + dir->AddressOfFunctions );
		const DWORD* names = reinterpret_cast< const DWORD* >( base + dir->AddressOfNames );
		const WORD* ords = reinterpret_cast< const WORD* > ( base + dir->AddressOfNameOrdinals );

		const DWORD nFuncs = dir->NumberOfFunctions;
		const DWORD nNames = dir->NumberOfNames;
		const WORD  baseOrd = static_cast< WORD >( dir->Base );

		/* this vector will contain all the exports that will then be handled by the PDB Parser */
		std::vector<eat_desc> exports;

		/* Named exports */
		for ( DWORD i = 0; i < nNames; ++i )
		{
			WORD idx = ords[i];
			if ( idx >= nFuncs ) continue;

			DWORD frva = funcs[idx];

			eat_desc e{};
			e.name = reinterpret_cast< const char* >( base + names[i] );
			e.ordinal = static_cast< WORD >( baseOrd + idx );

			// Inline "rva_in": forwarder if frva in [dirRva, dirRva + dirSize)
			if ( ( frva - dirRva ) < dirSize ) {
				e.rva = 0;
				e.forwarder = reinterpret_cast< const char* >( base + frva );
			}
			else {
				e.rva = frva;
				e.forwarder = nullptr;
			}

			// TODO: your “turn EAT into IAT” handling here (e.g., record e and later patch a slot)
			//std::cout << "Export: " << e.name << " | RVA " << std::hex << e.rva << "\n";
			exports.push_back( e );
		}


		/* handling each export */
		for ( const auto& e : exports )
		{
			/* checking if the export is a PM export + checking if it's special */
			bool is_special = false;
			myeat descriptor = {  };
			std::vector<std::string> components = split( e.name, '#' );
			if ( components.size( ) < 2 || components[1] != PerfectMapper_Magic ) continue;
			if ( std::string( e.name ).find( '@' ) != std::string::npos ) is_special = true;

			/* handling the export */
			if ( !pm_eat_handler( local_image, { components, e }, is_special ) )
				std::cout << "(-) Failed --> " << e.name << std::endl;
		}

		return true;
	}


	/* from seg off into RVA */
	uintptr_t to_va( const std::string& module_name, uint16_t seg, uint32_t off )
	{
		IMAGE_DOS_HEADER      dos_header = {};
		IMAGE_NT_HEADERS64    nt_headers = {};
		IMAGE_SECTION_HEADER  sec_header = {};

		/**/
		// Get loaded base of the kernel module (kernel virtual address) */
		uintptr_t base = kdmUtils::GetKernelModuleAddress( module_name );
		if ( !base ) return 0;

		/* Read DOS header */
		if ( !intel_driver::ReadMemory( base, &dos_header, sizeof( dos_header ) ) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ) return 0;

		/* Read NT headers */
		uintptr_t nt_addr = base + dos_header.e_lfanew;
		if ( !intel_driver::ReadMemory( nt_addr, &nt_headers, sizeof( nt_headers ) ) || nt_headers.Signature != IMAGE_NT_SIGNATURE ) return 0;

		/* PDB segments are 1-based indices into section table */
		WORD num_sections = nt_headers.FileHeader.NumberOfSections;
		if ( seg == 0 || seg > num_sections ) return 0;

		/* Read that section header */
		uintptr_t first_sec_addr = nt_addr + FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) + nt_headers.FileHeader.SizeOfOptionalHeader;
		uintptr_t this_sec_addr = first_sec_addr + ( seg - 1 ) * sizeof( IMAGE_SECTION_HEADER );
		if ( !intel_driver::ReadMemory( this_sec_addr, &sec_header, sizeof( sec_header ) ) ) return 0;

		/* Return kernel VA for the symbol */
		uint32_t rva = sec_header.VirtualAddress + off;
		return base + static_cast< uintptr_t >( rva );
	}


	/* map ( singe call --> map ) */
	uintptr_t map( bool destroy_hdrs = true )
	{
		/* getting the headers & needed information */
		NTSTATUS status = 0;
		this->dos	= ( PIMAGE_DOS_HEADER )drv_bytes.data( );
		this->nt	= ( PIMAGE_NT_HEADERS64 )( ( uintptr_t )this->dos + this->dos->e_lfanew );
		if ( this->nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) { return 0; }
		this->size = this->nt->OptionalHeader.SizeOfImage;
		
		/* allocating the image temporarily */
		this->base = ( BYTE* )VirtualAlloc( nullptr, this->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
		if ( !this->base ) { return 1; }

		/* getting needed information */
		DWORD virt_hdr_size = ( IMAGE_FIRST_SECTION( this->nt ) )->VirtualAddress;
		this->size = this->size - ( destroy_hdrs ? virt_hdr_size : 0 );

		/* allocating the kernel memory */
		if ( !intel_driver::IsRunning( ) ) { return 2; }
		this->krnl_base = intel_driver::AllocatePool( nt::POOL_TYPE::NonPagedPool, this->size );
		if ( !this->krnl_base ) { VirtualFree( this->base, 0, MEM_RELEASE ); return 0; }


		/* mapping the image */
		do
		{
			/* copying the image headers */
			memcpy( this->base, this->drv_bytes.data( ), nt->OptionalHeader.SizeOfHeaders );

			/* copy image sections */
			const PIMAGE_SECTION_HEADER curr_img_sec = IMAGE_FIRST_SECTION( this->nt );
			for ( auto i = 0; i < this->nt->FileHeader.NumberOfSections; ++i ) {
				if ( ( curr_img_sec[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) > 0 )
					continue;

				auto local_section = reinterpret_cast< void* >( reinterpret_cast< ULONG64 >( this->base ) + curr_img_sec[i].VirtualAddress );
				memcpy( local_section, reinterpret_cast< void* >( reinterpret_cast< ULONG64 >( this->drv_bytes.data() ) + curr_img_sec[i].PointerToRawData ), curr_img_sec[i].SizeOfRawData );
			}


			/* saving the real base ( also checking if we have to destroy the PE headers ) */
			ULONG64 realBase = this->krnl_base;
			if ( destroy_hdrs ) { this->krnl_base -= virt_hdr_size; }


			/* relocating the image given the delta */
			reloc_img_by_delta( portable_executable::GetRelocs( this->base ), this->krnl_base - this->nt->OptionalHeader.ImageBase );


			/* fixing the security cookie */
			if ( !fix_sec_cookie( this->base, this->krnl_base ) )
			{
				kdmLog( L"[-] Failed to fix cookie" << std::endl );
				return 3;
			}


			/* resolving the imports */
			if ( !res_imports( portable_executable::GetImports( this->base ) ) ) {
				kdmLog( L"[-] Failed to resolve imports" << std::endl );
				this->krnl_base = realBase;
				break;
			}
			

			/* resolve Perfect Mapper EAT into IAT */
			if ( !turn_eat_into_iat( this->base ) )
			{
				kdmLog( L"[-] ThePerfectInjector failed to fix EAT!" << std::endl );
				this->krnl_base = realBase;
				break;
			}


			/* writing the mapped image into kernel memory */
			if ( !intel_driver::WriteMemory( realBase, ( PVOID )( ( uintptr_t )this->base + ( destroy_hdrs ? virt_hdr_size : 0 ) ), this->size ) ) {
				kdmLog( L"[-] Failed to write local image to remote image" << std::endl );
				this->krnl_base = realBase;
				break;
			}


			/* getting the address of the entry point */
			const ULONG64 address_of_entry_point = this->krnl_base + this->nt->OptionalHeader.AddressOfEntryPoint;
			kdmLog( L"[<] Calling DriverEntry 0x" << reinterpret_cast< void* >( address_of_entry_point ) << std::endl );


			/* CALL ENTRY POINT */
			if ( !intel_driver::CallKernelFunction( &status, address_of_entry_point, realBase, 0 ) ) {
				kdmLog( L"[-] Failed to call driver entry" << std::endl );
				this->krnl_base = realBase;
				break;
			}


			/* freeing the allocated memory if the user needs to */
			bool free_status = false;
			if ( this->free )
			{
				free_status = intel_driver::FreePool( realBase );

				if ( free_status ) {
					kdmLog( L"[+] Memory has been released" << std::endl );
				}
				else {
					kdmLog( L"[-] WARNING: Failed to free memory!" << std::endl );
				}
			}
			

			/* freeing the locally allocated memory */
			VirtualFree( this->base, 0, MEM_RELEASE );
			return 0;

		} while ( false );


		/* cleanup + return error */
		bool free_status = false;
		VirtualFree( this->base, 0, MEM_RELEASE );
		free_status = intel_driver::FreePool( this->krnl_base );
		return 4;
	}


	/* this will toggle the pdb parsing */
	__forceinline void set_pdb_parsing( bool toggle ) { this->pdb_parsing = toggle; }
	__forceinline bool get_pdb_parsing( ) { return this->pdb_parsing; }

	/* this will toggle the freeing after entry point call */
	__forceinline void set_freeing( bool toggle ) { this->free = toggle; }
	__forceinline bool get_freeing( ) { return this->free; }

	/* unloading the intel driver */
	__forceinline ~PMapper( ) { intel_driver::Unload( ); }

private:

	/* attributes */
	std::vector<BYTE> drv_bytes;
	bool pdb_parsing = true;
	bool free = false;

	/* nt image */
	BYTE*					base		= NULL;
	ULONG					size		= 0;
	uintptr_t				krnl_base	= 0;
	PIMAGE_DOS_HEADER		dos			= NULL;
	PIMAGE_NT_HEADERS64		nt			= NULL;
	PIMAGE_SECTION_HEADER	sec			= NULL;
	std::unordered_map<std::string, PPDBParser> active_parsers;

};