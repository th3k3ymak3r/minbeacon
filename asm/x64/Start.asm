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
GLOBAL Start

;;
;; Import
;;
EXTERN Entry

[SECTION .text$A]

;;
;; Shellcode entrypoint
;;
Start:
	;;
	;; Prepare the stack
	;;
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	;;
	;; Execute C entrypoint
	;;
	sub	rsp, 020h
	call	Entry

	;;
	;; Restore stack
	;;
	mov	rsp, rsi
	pop	rsi

	;;
	;; Return
	;;
	ret
