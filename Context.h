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
	/* AES & HMAC Keys */
	union
	{
		BYTE	Key[ 32 ];
		BYTE	Aes[ 16 ];
		BYTE	Mac[ 16 ];
	};
	/* Static */
	ULONG	Bid;

	/* Libraries */
	PVOID	K32;
	PVOID	C32;
	PVOID	Adv;
} MINBEACON_CTX, *PMINBEACON_CTX ; 
