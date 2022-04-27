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
 * Searches for the module in memory. If it
 * is loaded, it returns the pointer to its
 * base address.
 *
 * If not, the it returns NULL.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 NameHash );
