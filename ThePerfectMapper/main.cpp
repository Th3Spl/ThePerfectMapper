
//
// inclusions
//
#include ".\mapper.h"


/* entry point */
int main( int argc, const char** argv )
{
	/* mapping the driver */
	//PPDBParser parser( "ntoskrnl.exe" );
	//
	//if ( !parser.is_initialized( ) )
	//{
	//	std::cout << "(-) Could not initialize the parser" << std::endl;
	//	return 1;
	//}
	//std::cout << "(+) Parser initialized correctly" << std::endl;
	//auto xx = parser.find_struct_field( "_EPROCESS", "ActiveProcessLinks" );
	//auto func = parser.find_symbol( "MmMapIoSpace" );
	//if ( !xx ) return 1;
	//std::cout << "..." << std::hex << *xx << std::endl;
	//if ( !func ) return 1;
	//std::cout << "...." << std::endl;

	PMapper mapper( ".\\TestDrv.sys" );
	if ( !mapper.map( ) ) std::cout << "(+) Image mapped successfully..." << std::endl;
	else std::cout << "(-) Could not map the driver!" << std::endl;
	return 0;
}