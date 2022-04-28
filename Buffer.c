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
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Create a buffer object.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID )
{
	API	Api;

	PBUFFER	Buf = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Build Stack API Table */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );

	/* Allocate an object of memory to hold a buffer structure */
	if ( ( Buf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( BUFFER ) ) ) != NULL ) {
		/* Initialize */
		Buf->Length = 0;
		Buf->Buffer = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return C_PTR( Buf );
};

/*!
 *
 * Purpose:
 *
 * Frees a buffer object.
 *
!*/
D_SEC( B ) VOID BufferRemove( _In_ PBUFFER Buffer )
{
	API	Api;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Build Stack API Table */
	Api.RtlFreeHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Free "buffer" and structures */
	Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buffer->Buffer );
	Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buffer );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Extend the size of the buffer.
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER Buffer, _In_ UINT32 Length )
{
	API	Api;
	BUFFER	Buf;

	BOOLEAN	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Build Stack API Table */
	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );

	/* Do we have a buffer? */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Length );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length );
	};

	/* Did we succeed? */
	if ( Buf.Buffer != NULL ) {
		/* Set a new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Set a new size */
		Buffer->Length = Buffer->Length + Length;

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Appends a buffer of specified length.
 *
!*/
D_SEC( B ) BOOL BufferAddRaw( _In_ PBUFFER BufObj, _In_ PVOID Buffer, _In_ UINT32 Length )
{
	API	Api;
	BUFFER	Buf;

	BOOLEAN	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Build Stack API Table */
	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );

	/* Do we have a "buffer"? */
	if ( BufObj->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, BufObj->Buffer, BufObj->Length + Length );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length );
	};

	/* Did we succeed ? */
	if ( Buf.Buffer != NULL ) {
		/* Set a new pointer */
		BufObj->Buffer = C_PTR( Buf.Buffer );

		/* Copy over our buffer */
		__builtin_memcpy( C_PTR( U_PTR( BufObj->Buffer ) + BufObj->Length ), Buffer, Length );

		/* Set new size */
		BufObj->Length = BufObj->Length + Length;

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Append a UINT32 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI32( _In_ PBUFFER BufObj, _In_ UINT32 Value )
{
	return BufferAddRaw( BufObj, &Value, sizeof( UINT32 ) );
};

/*!
 *
 * Purpose:
 *
 * Append a UINT16 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI16( _In_ PBUFFER BufObj, _In_ UINT16 Value )
{
	return BufferAddRaw( BufObj, &Value, sizeof( UINT16 ) );
};

/*
 *
 * Purpose:
 *
 * Append a UINT8 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI8( _In_ PBUFFER BufObj, _In_ UINT8 Value )
{
	return BufferAddRaw( BufObj, &Value, sizeof( UINT8 ) );
};
