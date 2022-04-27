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
GLOBAL _Start

;;
;; Import
;;
EXTERN _Entry

[SECTION .text$A]

;;
;; Shellcode entrypoint
;;
_Start:
	;;
	;; Prepare the stack
	;;
	push	ebp
	mov	ebp, esp

	;;
	;; Execute C entrypoint
	;;
	call	_Entry

	;;
	;; Restore stack
	;;
	mov	esp, ebp
	pop	ebp

	;;
	;; Return
	;;
	ret
