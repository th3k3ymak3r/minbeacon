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
 * Searches for the export in a PE module.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ UINT32 NameHash );
