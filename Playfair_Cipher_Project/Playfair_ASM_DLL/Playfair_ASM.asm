; =================================================================================
; FILE: Playfair_ASM.asm
; DESCRIPTION: Optimized AVX2 Playfair (x64) - aligned stack + SysV fixes
; =================================================================================

.data
    ALIGN 16
    ; Character Masks
    MASK_ZERO       DB 32 DUP(00h)
    
    ; Math Constants for AVX
    ; Multiplier for division by 5: (x * 205) >> 10
    MASK_RECIP_5_DWORD DD 8 DUP(000000CDh) ; 205
    MASK_FIVE_DWORD    DD 8 DUP(00000005h)
    MASK_ONE           DD 8 DUP(00000001h)
    MASK_FOUR_DWORD    DD 8 DUP(00000004h)
    MASK_FIVE          DD 8 DUP(00000005h)

.code

; =================================================================================
; Helper: strlen_asm (Scalar)
; Input: RCX -> pointer to string
; Output: RAX -> length (bytes before null)
; =================================================================================
strlen_asm PROC PRIVATE
    mov r8, rcx
    xor rax, rax
STRLEN_LOOP:
    cmp BYTE PTR [r8], 0
    je STRLEN_END
    inc rax
    inc r8
    jmp STRLEN_LOOP
STRLEN_END:
    ret
strlen_asm ENDP

; =================================================================================
; Helper: normalize_text_scalar (Safe)
; Inputs:
;   RCX -> input pointer
;   RDX -> output pointer
; Behavior:
;   - Uppercases ASCII letters
;   - Converts 'J' to 'I'
;   - Skips non-letters
;   - Writes null terminator to output
; =================================================================================
normalize_text_scalar PROC PRIVATE
    xor r8, r8  ; Input Index
    xor r9, r9  ; Output Index

NORM_LOOP:
    movzx eax, BYTE PTR [rcx + r8]
    test al, al
    jz NORM_DONE

    ; Check range 'A'-'Z'
    cmp al, 'A'
    jl CHECK_LOWER
    cmp al, 'Z'
    jle PROCESS_CHAR

CHECK_LOWER:
    cmp al, 'a'
    jl SKIP_CHAR
    cmp al, 'z'
    jg SKIP_CHAR
    sub al, 32 ; Convert to Upper

PROCESS_CHAR:
    ; J -> I
    cmp al, 'J'
    jne STORE_CHAR
    mov al, 'I'

STORE_CHAR:
    mov BYTE PTR [rdx + r9], al
    inc r9

SKIP_CHAR:
    inc r8
    jmp NORM_LOOP

NORM_DONE:
    mov BYTE PTR [rdx + r9], 0
    ret
normalize_text_scalar ENDP

; =================================================================================
; BuildKeyTable_ASM_Internal
; System V calling convention:
;   RDI = table_ptr (arg1)
;   RSI = key_ptr   (arg2)
; This function reserves an aligned stack frame and saves callee-saved regs.
; Local layout (using [rsp] region):
;   - used array at [rsp] (256 bytes)
;   - normalized key at [rsp+256]
; =================================================================================
BuildKeyTable_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp

    ; Reserve aligned stack: 1536 bytes (multiple of 32) for locals
    ; Save callee-saved registers into rbp-relative slots
    sub rsp, 1536

    ; Save rbx (we will use), keep rdi/rsi as args (SysV)
    mov QWORD PTR [rbp - 8], rbx

    ; 1. Clear Used Array (at [rsp])
    lea rdx, [rsp]
    mov rcx, 256
    xor rax, rax
CLEAR_USED:
    mov BYTE PTR [rdx + rax], 0
    inc rax
    cmp rax, rcx
    jl CLEAR_USED

    ; 2. Normalize Key
    lea rdx, [rsp + 256]    ; output -> normalized key buffer
    mov rcx, rsi            ; input -> original key (RSI)
    call normalize_text_scalar

    ; 3. Fill Table
    lea rsi, [rsp + 256]    ; normalized key input
    xor r10, r10            ; r10 = index into normalized key
    xor r11, r11            ; r11 = table write index (0..24)
    lea rbx, [rsp]          ; used array base

FILL_KEY_LOOP:
    movzx eax, BYTE PTR [rsi + r10]
    test al, al
    jz FILL_ALPHABET

    ; Save ASCII char in R8D before modifying EAX
    mov r8d, eax

    sub al, 'A' ; Convert to Index (0..25)
    movzx ecx, BYTE PTR [rbx + rax] ; Check Used[Index]
    test cl, cl
    jnz NEXT_KEY_CHAR

    mov BYTE PTR [rbx + rax], 1
    ; Store the ASCII char (r8b), NOT the index (al)
    mov BYTE PTR [rdi + r11], r8b
    inc r11

NEXT_KEY_CHAR:
    inc r10
    cmp r11, 25
    je BUILD_DONE
    jmp FILL_KEY_LOOP

FILL_ALPHABET:
    mov r10b, 'A'

ALPHA_LOOP:
    cmp r10b, 'Z'
    jg BUILD_DONE

    cmp r10b, 'J'
    je NEXT_ALPHA_CHAR

    movzx eax, r10b
    sub al, 'A' ; Convert to Index
    movzx ecx, BYTE PTR [rbx + rax]
    test cl, cl
    jnz NEXT_ALPHA_CHAR

    mov BYTE PTR [rbx + rax], 1
    mov BYTE PTR [rdi + r11], r10b ; Store ASCII
    inc r11

NEXT_ALPHA_CHAR:
    inc r10b
    cmp r11, 25
    jl ALPHA_LOOP

BUILD_DONE:
    ; Restore rbx
    mov rbx, QWORD PTR [rbp - 8]
    add rsp, 1536
    pop rbp
    ret
BuildKeyTable_ASM_Internal ENDP

; =================================================================================
; EncryptPlayfair_ASM_Internal
; System V calling convention:
;   RDI = table_ptr     (arg1)
;   RSI = plaintext     (arg2)
;   RDX = ciphertext    (arg3)  <- output pointer
;   RCX = index_LUT     (arg4)
; Local layout (we reserve 4288 bytes, a multiple of 32):
;   - xmm save area at [rsp + 0 .. +159]
;   - scratch/pad area at [rsp .. +4095] with normalized buffer at +2048
; =================================================================================
EncryptPlayfair_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp

    ; Reserve aligned stack: 4288 bytes (32 * 134)
    sub rsp, 4288

    ; Save callee-saved GPRs to rbp-relative slots
    mov QWORD PTR [rbp - 8], r12
    mov QWORD PTR [rbp - 16], r13
    mov QWORD PTR [rbp - 24], r14
    mov QWORD PTR [rbp - 32], r15
    mov QWORD PTR [rbp - 40], rbx

    ; Save XMM6..XMM15 into low part of reserved area (aligned)
    vmovdqu xmmword ptr [rsp + 0], xmm6
    vmovdqu xmmword ptr [rsp + 16], xmm7
    vmovdqu xmmword ptr [rsp + 32], xmm8
    vmovdqu xmmword ptr [rsp + 48], xmm9
    vmovdqu xmmword ptr [rsp + 64], xmm10
    vmovdqu xmmword ptr [rsp + 80], xmm11
    vmovdqu xmmword ptr [rsp + 96], xmm12
    vmovdqu xmmword ptr [rsp + 112], xmm13
    vmovdqu xmmword ptr [rsp + 128], xmm14
    vmovdqu xmmword ptr [rsp + 144], xmm15

    ; Map arguments to internal registers for System V:
    mov r12, rdi   ; r12 := table_ptr (arg1)
    ; rsi already holds plaintext (arg2)
    mov rdi, rdx   ; rdi := ciphertext buffer (arg3)
    mov r14, rcx   ; r14 := index LUT (arg4)

    ; --- 1. Normalize Input ---
    lea rdx, [rsp + 2048]     ; output normalized to rsp+2048
    mov rcx, rsi              ; input pointer -> RCX for helper
    call normalize_text_scalar

    ; --- 2. Pad Plaintext ---
    lea rsi, [rsp + 2048]     ; normalized input
    lea rbx, [rsp]            ; padded output base at rsp
    xor r10, r10
    xor r11, r11

PAD_LOOP_E:
    movzx eax, BYTE PTR [rsi + r10]
    test al, al
    jz PAD_FINISH_E

    mov BYTE PTR [rbx + r11], al
    inc r11
    inc r10

    movzx ecx, BYTE PTR [rsi + r10]
    test cl, cl
    jz PAD_CHECK_ODD_E

    cmp al, cl
    jne PAD_STORE_SECOND_E

    mov BYTE PTR [rbx + r11], 'X'
    inc r11
    jmp PAD_LOOP_E

PAD_STORE_SECOND_E:
    mov BYTE PTR [rbx + r11], cl
    inc r11
    inc r10
    jmp PAD_LOOP_E

PAD_CHECK_ODD_E:
    test r11, 1
    jz PAD_FINISH_E
    mov BYTE PTR [rbx + r11], 'X'
    inc r11

PAD_FINISH_E:
    mov BYTE PTR [rbx + r11], 0
    mov r15, r11        ; r15 = padded length

    ; Safety: if length is zero, just write empty and exit
    cmp r15, 0
    je ENC_DONE_SAFE

    ; --- 3. Encryption Loop ---
    xor r13, r13        ; r13 = output index

ENC_LOOP:
    cmp r13, r15
    jae ENC_DONE

    ; Load up to 16 bytes from padded buffer at [rbx + r13] into xmm0
    vmovdqu xmm0, XMMWORD PTR [rbx + r13]

    ; Place the 16 bytes into temp at [rsp + 2048] for transform
    lea rax, [rsp + 2048]
    vmovdqu xmmword ptr [rax], xmm0

    xor rcx, rcx
GATHER_ENC:
    movzx edx, BYTE PTR [rax + rcx]     ; cleaned byte
    movzx edx, BYTE PTR [r14 + rdx]     ; map through LUT -> index 0..24
    mov r8, rax
    add r8, rcx
    mov BYTE PTR [r8 + 32], dl          ; write gathered indices to rax+32..47
    inc rcx
    cmp rcx, 16
    jl GATHER_ENC

    lea r8, [rax + 32]
    vmovdqu xmm1, xmmword ptr [r8]      ; gather block

    vpunpcklbw xmm2, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm2, xmm2
    vpunpckhbw xmm3, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm3, xmm3

    vmovdqa xmm4, xmm2
    vpmulld xmm4, xmm4, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm4, xmm4, 10
    vmovdqa xmm5, xmm4
    vpmulld xmm5, xmm5, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm5, xmm2, xmm5

    vmovdqa xmm6, xmm3
    vpmulld xmm6, xmm6, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm6, xmm6, 10
    vmovdqa xmm7, xmm6
    vpmulld xmm7, xmm7, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm7, xmm3, xmm7

    vpcmpeqd xmm8, xmm4, xmm6 
    vpcmpeqd xmm9, xmm5, xmm7 
    vpcmpeqd xmm10, xmm9, XMMWORD PTR MASK_ZERO
    vpand xmm10, xmm10, xmm8 
    vpcmpeqd xmm11, xmm8, XMMWORD PTR MASK_ZERO
    vpand xmm11, xmm11, xmm9 
    vpor xmm13, xmm8, xmm9
    vpcmpeqd xmm12, xmm13, XMMWORD PTR MASK_ZERO 

    vmovdqa xmm13, xmm5
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm5, xmm5, xmm13, xmm10

    vmovdqa xmm13, xmm7
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm7, xmm7, xmm13, xmm10

    vmovdqa xmm13, xmm4
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm4, xmm4, xmm13, xmm11

    vmovdqa xmm13, xmm6
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm6, xmm6, xmm13, xmm11

    vmovdqa xmm13, xmm5
    vpblendvb xmm5, xmm5, xmm7, xmm12
    vpblendvb xmm7, xmm7, xmm13, xmm12

    vmovdqa xmm13, xmm4
    vpmulld xmm13, xmm13, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm13, xmm13, xmm5

    vmovdqa xmm14, xmm6
    vpmulld xmm14, xmm14, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm14, xmm14, xmm7

    vpackusdw xmm0, xmm13, xmm14
    vpackuswb xmm0, xmm0, xmm0

    lea rax, [rsp + 2048]
    vmovdqu xmmword ptr [rax], xmm0

    xor rcx, rcx
FINAL_LOOKUP_ENC:
    movzx edx, BYTE PTR [rax + rcx] 
    movzx edx, BYTE PTR [r12 + rdx] 
    lea r9, [rdi + r13]
    mov BYTE PTR [r9 + rcx], dl
    inc rcx
    cmp rcx, 16
    jl FINAL_LOOKUP_ENC

    add r13, 16
    ; Safety: if r13 grows past a large number unexpectedly, bail (protect against corrupted r15)
    cmp r13, 1000000h
    jne CONTINUE_ENC_SAFE
    ; if we hit here, something went wrong - break out
    jmp ENC_DONE
CONTINUE_ENC_SAFE:
    jmp ENC_LOOP

ENC_DONE:
ENC_DONE_SAFE:
    mov BYTE PTR [rdi + r13], 0

    ; Restore XMM regs
    vmovdqu xmm6, xmmword ptr [rsp + 0]
    vmovdqu xmm7, xmmword ptr [rsp + 16]
    vmovdqu xmm8, xmmword ptr [rsp + 32]
    vmovdqu xmm9, xmmword ptr [rsp + 48]
    vmovdqu xmm10, xmmword ptr [rsp + 64]
    vmovdqu xmm11, xmmword ptr [rsp + 80]
    vmovdqu xmm12, xmmword ptr [rsp + 96]
    vmovdqu xmm13, xmmword ptr [rsp + 112]
    vmovdqu xmm14, xmmword ptr [rsp + 128]
    vmovdqu xmm15, xmmword ptr [rsp + 144]

    ; Restore saved GPRs
    mov r12, QWORD PTR [rbp - 8]
    mov r13, QWORD PTR [rbp - 16]
    mov r14, QWORD PTR [rbp - 24]
    mov r15, QWORD PTR [rbp - 32]
    mov rbx, QWORD PTR [rbp - 40]

    add rsp, 4288
    vzeroupper
    pop rbp
    ret
EncryptPlayfair_ASM_Internal ENDP

; =================================================================================
; DecryptPlayfair_ASM_Internal
; System V calling convention:
;   RDI = table_ptr     (arg1)
;   RSI = ciphertext    (arg2)
;   RDX = plaintext     (arg3)  <- output pointer
;   RCX = index_LUT     (arg4)
; Layout mirrors EncryptPlayfair.
; =================================================================================
DecryptPlayfair_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp

    ; Reserve aligned stack: 4288 bytes
    sub rsp, 4288

    ; Save callee-saved GPRs
    mov QWORD PTR [rbp - 8], r12
    mov QWORD PTR [rbp - 16], r13
    mov QWORD PTR [rbp - 24], r14
    mov QWORD PTR [rbp - 32], r15
    mov QWORD PTR [rbp - 40], rbx

    ; Save XMM6..XMM15
    vmovdqu xmmword ptr [rsp + 0], xmm6
    vmovdqu xmmword ptr [rsp + 16], xmm7
    vmovdqu xmmword ptr [rsp + 32], xmm8
    vmovdqu xmmword ptr [rsp + 48], xmm9
    vmovdqu xmmword ptr [rsp + 64], xmm10
    vmovdqu xmmword ptr [rsp + 80], xmm11
    vmovdqu xmmword ptr [rsp + 96], xmm12
    vmovdqu xmmword ptr [rsp + 112], xmm13
    vmovdqu xmmword ptr [rsp + 128], xmm14
    vmovdqu xmmword ptr [rsp + 144], xmm15

    ; Map arguments
    mov r12, rdi   ; table
    ; rsi -> ciphertext (arg2)
    mov rdi, rdx   ; rdi := plaintext buffer (arg3)
    mov r14, rcx   ; index LUT (arg4)

    mov rcx, rsi
    call strlen_asm
    mov r15, rax ; Length

    xor r13, r13

DEC_LOOP:
    cmp r13, r15
    jae DEC_DONE

    vmovdqu xmm0, XMMWORD PTR [rsi + r13]

    lea rax, [rsp + 2048]
    vmovdqu xmmword ptr [rax], xmm0

    xor rcx, rcx
GATHER_DEC:
    movzx edx, BYTE PTR [rax + rcx]
    movzx edx, BYTE PTR [r14 + rdx]
    mov r8, rax
    add r8, rcx
    mov BYTE PTR [r8 + 32], dl
    inc rcx
    cmp rcx, 16
    jl GATHER_DEC

    lea r8, [rax + 32]
    vmovdqu xmm1, xmmword ptr [r8]

    vpunpcklbw xmm2, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm2, xmm2
    vpunpckhbw xmm3, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm3, xmm3

    vmovdqa xmm4, xmm2
    vpmulld xmm4, xmm4, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm4, xmm4, 10
    vmovdqa xmm5, xmm4
    vpmulld xmm5, xmm5, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm5, xmm2, xmm5

    vmovdqa xmm6, xmm3
    vpmulld xmm6, xmm6, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm6, xmm6, 10
    vmovdqa xmm7, xmm6
    vpmulld xmm7, xmm7, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm7, xmm3, xmm7

    vpcmpeqd xmm8, xmm4, xmm6
    vpcmpeqd xmm9, xmm5, xmm7
    vpcmpeqd xmm10, xmm9, XMMWORD PTR MASK_ZERO
    vpand xmm10, xmm10, xmm8
    vpcmpeqd xmm11, xmm8, XMMWORD PTR MASK_ZERO
    vpand xmm11, xmm11, xmm9
    vpor xmm13, xmm8, xmm9
    vpcmpeqd xmm12, xmm13, XMMWORD PTR MASK_ZERO

    vmovdqa xmm13, xmm5
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    ; Blend for decrements: implement using vpblendvb similarly to encrypt but adjusted
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm10
    vpblendvb xmm5, xmm5, xmm13, xmm10

    vmovdqa xmm13, xmm7
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm10
    vpblendvb xmm7, xmm7, xmm13, xmm10

    vmovdqa xmm13, xmm4
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm11
    vpblendvb xmm4, xmm4, xmm13, xmm11

    vmovdqa xmm13, xmm6
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm11
    vpblendvb xmm6, xmm6, xmm13, xmm11

    vmovdqa xmm13, xmm5
    vpblendvb xmm5, xmm5, xmm7, xmm12
    vpblendvb xmm7, xmm7, xmm13, xmm12

    vmovdqa xmm13, xmm4
    vpmulld xmm13, xmm13, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm13, xmm13, xmm5

    vmovdqa xmm14, xmm6
    vpmulld xmm14, xmm14, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm14, xmm14, xmm7

    vpackusdw xmm0, xmm13, xmm14
    vpackuswb xmm0, xmm0, xmm0

    lea rax, [rsp + 2048]
    vmovdqu xmmword ptr [rax], xmm0

    xor rcx, rcx
FINAL_LOOKUP_DEC:
    movzx edx, BYTE PTR [rax + rcx]
    movzx edx, BYTE PTR [r12 + rdx]
    lea r9, [rdi + r13]
    mov BYTE PTR [r9 + rcx], dl
    inc rcx
    cmp rcx, 16
    jl FINAL_LOOKUP_DEC

    add r13, 16
    ; Safety guard
    cmp r13, 1000000h
    jne CONTINUE_DEC_SAFE
    jmp DEC_DONE
CONTINUE_DEC_SAFE:
    jmp DEC_LOOP

DEC_DONE:
    mov BYTE PTR [rdi + r13], 0

    ; Restore XMM regs
    vmovdqu xmm6, xmmword ptr [rsp + 0]
    vmovdqu xmm7, xmmword ptr [rsp + 16]
    vmovdqu xmm8, xmmword ptr [rsp + 32]
    vmovdqu xmm9, xmmword ptr [rsp + 48]
    vmovdqu xmm10, xmmword ptr [rsp + 64]
    vmovdqu xmm11, xmmword ptr [rsp + 80]
    vmovdqu xmm12, xmmword ptr [rsp + 96]
    vmovdqu xmm13, xmmword ptr [rsp + 112]
    vmovdqu xmm14, xmmword ptr [rsp + 128]
    vmovdqu xmm15, xmmword ptr [rsp + 144]

    ; Restore saved GPRs
    mov r12, QWORD PTR [rbp - 8]
    mov r13, QWORD PTR [rbp - 16]
    mov r14, QWORD PTR [rbp - 24]
    mov r15, QWORD PTR [rbp - 32]
    mov rbx, QWORD PTR [rbp - 40]

    add rsp, 4288
    vzeroupper
    pop rbp
    ret
DecryptPlayfair_ASM_Internal ENDP

END
