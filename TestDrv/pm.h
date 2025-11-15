/* Note: you must use extern if you declare it in a different .h */
#pragma once


/* includes a simple iniitalization check */
#define pm_iat_check( check_name ) \
	__pragma(comment(linker, "/EXPORT:#PM#@check" "=" #check_name ",DATA")) \
	char check_name;

/* Adds a PDB IAT in the EAT for a function ( needs an existing typedef ) */
#define pm_iat(func_name, _typedef, _src_module, _src_name) \
    __pragma(comment(linker, "/EXPORT:#PM#" #func_name "#" _src_module "#" _src_name "=" #func_name ",DATA")) \
	_typedef func_name;

/* Adds a PDB IAT in the EAT for a function ( does not need an existing typedef ) */
#define pm_iat_ex( func_name, ret, call_conv, type_name, args, _src_module, _src_name) \
	__pragma(comment(linker, "/EXPORT:#PM#" #func_name "#" _src_module "#" _src_name "=" #func_name ",DATA")) \
	typedef ret( call_conv* type_name) args; \
	type_name func_name;

/* Adds a PDB IAT in the EAT for an offset within a structure (ex: _EPROCESS->DirectoryTableBase ) */
#define pm_iat_offset( _name, _src_module, _src_struct, _src_comp_name ) \
	__pragma( comment( linker, "/EXPORT:#PM#" #_name "#@offset#" _src_module "#" _src_struct "#" _src_comp_name "=" #_name ",DATA" )) \
	unsigned long long _name;

/* Adds a PDB IAT in the EAT for an offset within a structure with a specified type for the offset */
#define pm_iat_offset2( _name, _type, _src_module, _src_struct, _src_comp_name ) \
	__pragma( comment( linker, "/EXPORT:#PM#" #_name "#@offset#" _src_module "#" _src_struct "#" _src_comp_name "=" #_name ",DATA" )) \
	_type _name;