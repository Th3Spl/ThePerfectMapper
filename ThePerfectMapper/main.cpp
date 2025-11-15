
//
// inclusions
//
#include ".\mapper.h"


/* entry point */
int main( int argc, const char** argv )
{
	/* invalid usage */
	if ( argc < 2 )
	{
		std::cout << std::endl << "(-) Invalid parameters" << std::endl;
		std::cout << " - Usage: ThePerfectMapper.exe <drv_path>" << std::endl;
		return 1;
	}

	/* checking if the provided path exists */
	if ( !std::filesystem::exists( argv[1] ) || !std::filesystem::is_regular_file( argv[1] ) )
	{
		std::cout << "(-) Could not resolve the driver path!";
		return 1;
	}

	/* mapping the driver */
	PMapper mapper( argv[1] );
	uintptr_t status = mapper.map( );

	/* logging */
	if ( !status ) std::cout << "(+) Image mapped successfully..." << std::endl;
	else std::cout << "(-) Could not map the driver! [ Err: " << status << "]" << std::endl;
	return 0;
}