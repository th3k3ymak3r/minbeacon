;;
;; MINBEACON
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

;;
;; Export
;;
GLOBAL GetIp

[SECTION .text$C]

;;
;; Gets the address of itself.
;;
GetIp:
	;;
	;; Execute next instruction
	;;
	call	get_ret_addr

	get_ret_addr:
	;;
	;; Pop return address
	;;
	pop	rax

	;;
	;; Subtract difference
	;;
	sub	rax, 5

	;;
	;; Return
	;;
	ret

Leave:
	db 'ENDOFCODE'
