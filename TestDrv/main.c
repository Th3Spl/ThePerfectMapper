#include <ntifs.h>
#include ".\pm.h"


typedef void( __stdcall* _ExFreePoolWithTag )( PVOID, ULONG );
pm_iat_check( is_pm_initialized );
pm_iat( Test1337, _ExFreePoolWithTag, "ntoskrnl.exe", "ExFreePoolWithTag" );
pm_iat( smbios_pa, PPHYSICAL_ADDRESS, "ntoskrnl.exe", "WmipSMBiosTablePhysicalAddress" );
pm_iat_offset( eproc_ActiveProcessLinks, "ntoskrnl.exe", "_EPROCESS", "ActiveProcessLinks" );



NTSTATUS DriverEntry( PDRIVER_OBJECT drv_obj, PUNICODE_STRING str )
{
	drv_obj; str;
		
	if ( is_pm_initialized ) DbgPrintEx( 0, 0, "\n\n\n(+) PM Initialized correctly!\n" );
	else DbgPrintEx( 0, 0, "(-) Mapper did not initialize PM!\n" );


	DbgPrintEx( 0, 0, "[ PM ] ExFreePoolWithTag: 0x%p\n", Test1337 );
	DbgPrintEx( 0, 0, "[ KM ] ExFreePoolWithTag: 0x%p\n", ExFreePoolWithTag );
	DbgPrintEx( 0, 0, "[ PM ] WmipSMBiosTablePhysicalAddress: 0x%p\n", smbios_pa );
	DbgPrintEx( 0, 0, "[ PM ] WmipSMBiosTablePhysicalAddress value: 0x%llx\n", smbios_pa->QuadPart );
	DbgPrintEx( 0, 0, "[ PM ] offset test value: 0x%llx\n", eproc_ActiveProcessLinks );

	
	//Test1337( 1 );
	return 0;
}