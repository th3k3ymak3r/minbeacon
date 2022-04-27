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

/*!
 *
 * Purpose:
 *
 * Creates a random UINT32 integer 
 *
!*/
D_SEC( B ) UINT32 RandomInt32( VOID );

/*!
 *
 * Purpose:
 *
 * Fills a buffer with a random string of the
 * specified size.
 *
!*/
D_SEC( B ) VOID RandomString( _In_ PVOID Buffer, _In_ UINT32 Length );
