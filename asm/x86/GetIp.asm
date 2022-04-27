;;
;; MINBEACON
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 32]

;;
;; Export
;;
GLOBAL _GetIp

[SECTION .text$C]

;;
;; Gets the address of itself.
;;
_GetIp:
	;;
	;; Execute next instruction
	;;
	call	_get_ret_addr

	_get_ret_addr:
	;;
	;; Pop return address
	;;
	pop	eax

	;;
	;; Subtract difference
	;;
	sub	eax, 5

	;;
	;; Return
	;;
	ret

_Leave:
	db 'ENDOFCODE'
