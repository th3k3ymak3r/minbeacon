/*!
 *
 * MINBEACON
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

typedef struct
{
	LPVOID	Buffer;
	UINT32	Length;
} BUFFER, *PBUFFER ;

/*!
 *
 * Purpose:
 *
 * Create a buffer object.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID );

/*!
 *
 * Purpose:
 *
 * Frees a buffer object.
 *
!*/
D_SEC( B ) VOID BufferRemove( _In_ PBUFFER Buffer );

/*!
 *
 * Purpose:
 *
 * Extend the size of the buffer.
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER Buffer, _In_ UINT32 Length );

/*!
 *
 * Purpose:
 *
 * Appends a buffer of specified length.
 *
!*/
D_SEC( B ) BOOL BufferAddRaw( _In_ PBUFFER BufObj, _In_ PVOID Buffer, _In_ UINT32 Length );

/*!
 *
 * Purpose:
 *
 * Append a UINT32 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI32( _In_ PBUFFER BufObj, _In_ UINT32 Value );

/*!
 *
 * Purpose:
 *
 * Append a UINT16 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI16( _In_ PBUFFER BufObj, _In_ UINT16 Value );

/*
 *
 * Purpose:
 *
 * Append a UINT8 value.
 *
!*/
D_SEC( B ) BOOL BufferAddI8( _In_ PBUFFER BufObj, _In_ UINT8 Value );
