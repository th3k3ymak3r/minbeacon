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

/* Finds a function / variable / string address via its relative offset to GetIp() */
#define G_PTR( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast as a function / variable / string in a specific region of memory */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Cast as a pointer with the specified typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID ) x )

/* Arch Specific Macros */
#if defined( _WIN64 )
	/* Get the end of code: x64 */
	#define G_END( x )	U_PTR( GetIp( ) + 11 )
#else
	/* Get the end of code: x86 */
	#define G_END( x )	U_PTR( GetIp( ) + 10 )
#endif
