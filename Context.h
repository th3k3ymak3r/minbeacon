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
	UINT32	Bid;

	/* Libraries */
	HANDLE	K32;
	HANDLE	C32;
	HANDLE	Adv;
} MINBEACON_CTX, *PMINBEACON_CTX ; 
