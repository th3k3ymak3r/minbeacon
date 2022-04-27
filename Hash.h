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
 * Creates a DJB2 hash representation of the
 * input buffer and specified length. If a
 * length is not provided, it assumes it is
 * a NULL terminated string.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length );
