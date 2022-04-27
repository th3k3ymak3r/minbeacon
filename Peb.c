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
 * Searches for the module in memory. If it
 * is loaded, it returns the pointer to its
 * base address.
 *
 * If not, the it returns NULL.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 NameHash )
{
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get first linked list entry and header */
	Hdr = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	/* Enumerate the complete list */
	for ( ; Ent != Hdr ; Ent = Ent->Flink ) {
		Ldr = C_PTR( CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks ) );

		/* Compare the two names. If match, we return its base address */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == NameHash ) {
			/* Return Base Address */
			return C_PTR( Ldr->DllBase );
		};
	};
	return NULL;
};
