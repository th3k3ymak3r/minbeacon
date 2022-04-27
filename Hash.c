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

/*!
 *
 * Purpose:
 *
 * Creates a DJB2 hash representation of the
 * input buffer and specified length. If a
 * length is not provided, it assumes it is
 * a NULL terminated string.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	UINT8	Chr = 0;
	UINT32	Djb = 0;
	PUINT8	Str = NULL;

	/* Initial seed for DJB2 & Buffer */
	Djb = 5381;
	Str = C_PTR( Buffer );

	/* Loop through each character */
	while ( TRUE ) {
		/* Extract the current character */
		Chr = * Str;

		if ( ! Length ) {
			/* NULL terminated */
			if ( ! * Str ) {
				/* Leave the loop */
				break;
			};
		} else {
			/* Did we exceed the length of the buffer? */
			if ( ( UINT32 )( Str - ( PUINT8 ) Buffer ) >= Length ) {
				/* Leave the loop */
				break;
			};
			if ( ! * Str ) {
				/* Move onto next character */
				++Str; continue;
			};
		};
		/* Force to uppercase */
		if ( Chr >= 'a' ) {
			Chr -= 0x20;
		};

		/* Create the hash */
		Djb = ( ( Djb << 5 ) + Djb ) + Chr; ++Str;
	};
	/* Return */
	return Djb;
};
