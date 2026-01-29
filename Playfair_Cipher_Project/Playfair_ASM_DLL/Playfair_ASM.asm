; =================================================================================
; FILE: Playfair_ASM.asm
; DESCRIPTION: Optimized AVX2 Playfair (x64) - Windows (Microsoft x64) Convention
; =================================================================================

.data
    ALIGN 16
    ; Character Masks
    MASK_ZERO        DB 32 DUP(00h)
    
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
; Microsoft x64 Convention:
;   RCX = table_ptr (arg1)
;   RDX = key_ptr   (arg2)
; =================================================================================
BuildKeyTable_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp

    ; Windows wymaga zachowania RDI, RSI, RBX
    push rdi
    push rsi
    push rbx

    ; Przesuniêcie argumentów do rejestrów u¿ywanych w logice (mapowanie Windows -> Logic)
    mov rdi, rcx    ; RDI = table_ptr
    mov rsi, rdx    ; RSI = key_ptr

    ; Reserve aligned stack: 1536 bytes
    sub rsp, 1536 + 32 ; +32 for alignment padding safety if needed

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
    ; normalize_text_scalar expects: RCX=input, RDX=output
    lea rdx, [rsp + 256]    ; output -> normalized key buffer
    mov rcx, rsi            ; input -> original key (from RSI)
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

    mov r8d, eax

    sub al, 'A' ; Convert to Index (0..25)
    movzx ecx, BYTE PTR [rbx + rax] ; Check Used[Index]
    test cl, cl
    jnz NEXT_KEY_CHAR

    mov BYTE PTR [rbx + rax], 1
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
    add rsp, 1536 + 32
    
    ; Restore Windows Non-Volatile Registers
    pop rbx
    pop rsi
    pop rdi
    
    pop rbp
    ret
BuildKeyTable_ASM_Internal ENDP

; =================================================================================
; EncryptPlayfair_ASM_Internal (POPRAWIONA LOGIKA)
; Microsoft x64 Convention:
;   RCX = table_ptr      (arg1) -> R12
;   RDX = plaintext      (arg2) -> RSI
;   R8  = ciphertext     (arg3) -> RDI
;   R9  = index_LUT      (arg4) -> R14
; =================================================================================
EncryptPlayfair_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp
    sub rsp, 4096 

    ; Save callee-saved registers
    mov QWORD PTR [rbp - 8], r12
    mov QWORD PTR [rbp - 16], r13
    mov QWORD PTR [rbp - 24], r14
    mov QWORD PTR [rbp - 32], r15
    mov QWORD PTR [rbp - 40], rbx
    mov QWORD PTR [rbp - 48], rdi
    mov QWORD PTR [rbp - 56], rsi

    mov r12, rcx    ; Table Ptr
    mov rsi, rdx    ; Plaintext Ptr
    mov rdi, r8     ; Ciphertext Ptr
    mov r14, r9     ; LUT Ptr

    ; --- Normalize ---
    lea rdx, [rsp + 2048]
    mov rcx, rsi
    call normalize_text_scalar

    ; --- Padding ---
    lea rsi, [rsp + 2048]
    lea rbx, [rsp]
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

    cmp r15, 0
    je ENC_DONE

    xor r13, r13        ; Loop index

ENC_PAIR_LOOP:
    cmp r13, r15
    jae ENC_DONE

    ; Wczytaj parê
    movzx eax, BYTE PTR [rbx + r13]
    movzx ecx, BYTE PTR [rbx + r13 + 1]

    ; LUT (ASCII -> Index)
    movzx eax, BYTE PTR [r14 + rax]
    movzx ecx, BYTE PTR [r14 + rcx]

    ; --- Oblicz Row/Col dla Index 1 (EAX) ---
    mov dl, 5
    div dl          ; AX / 5 -> AL=Row, AH=Col
    mov r8b, al     ; Row1 zapisane w R8B
    
    ; FIX A2218: Przeniesienie AH -> AL -> R9B
    mov al, ah      
    mov r9b, al     ; Col1 zapisane w R9B

    ; --- Oblicz Row/Col dla Index 2 (ECX) ---
    mov eax, ecx
    mov dl, 5
    div dl          ; AX / 5 -> AL=Row, AH=Col
    mov r10b, al    ; Row2 zapisane w R10B

    ; FIX A2218: Przeniesienie AH -> AL -> R11B
    mov al, ah
    mov r11b, al    ; Col2 zapisane w R11B

    ; --- Logic ---
    cmp r8b, r10b
    je ENC_SAME_ROW
    cmp r9b, r11b
    je ENC_SAME_COL

    ; Rectangle
    mov al, r8b     ; Row1
    mov dl, 5
    mul dl
    add al, r11b    ; + Col2
    mov r8b, al     ; New Index 1

    mov al, r10b    ; Row2
    mov dl, 5
    mul dl
    add al, r9b     ; + Col1
    mov r9b, al     ; New Index 2
    jmp STORE_PAIR

ENC_SAME_ROW:
    inc r9b
    cmp r9b, 5
    jne CHECK_COL2_ROW
    mov r9b, 0
CHECK_COL2_ROW:
    inc r11b
    cmp r11b, 5
    jne CALC_INDEX_ROW
    mov r11b, 0
CALC_INDEX_ROW:
    mov al, r8b
    mov dl, 5
    mul dl
    add al, r9b
    mov r8b, al

    mov al, r10b
    mov dl, 5
    mul dl
    add al, r11b
    mov r9b, al
    jmp STORE_PAIR

ENC_SAME_COL:
    inc r8b
    cmp r8b, 5
    jne CHECK_ROW2_COL
    mov r8b, 0
CHECK_ROW2_COL:
    inc r10b
    cmp r10b, 5
    jne CALC_INDEX_COL
    mov r10b, 0
CALC_INDEX_COL:
    mov al, r8b
    mov dl, 5
    mul dl
    add al, r9b
    mov r8b, al

    mov al, r10b
    mov dl, 5
    mul dl
    add al, r11b
    mov r9b, al

STORE_PAIR:
    movzx eax, r8b
    mov r8b, BYTE PTR [r12 + rax]
    
    movzx eax, r9b
    mov r9b, BYTE PTR [r12 + rax]

    mov BYTE PTR [rdi + r13], r8b
    mov BYTE PTR [rdi + r13 + 1], r9b

    add r13, 2
    jmp ENC_PAIR_LOOP

ENC_DONE:
    mov BYTE PTR [rdi + r13], 0

    mov r12, QWORD PTR [rbp - 8]
    mov r13, QWORD PTR [rbp - 16]
    mov r14, QWORD PTR [rbp - 24]
    mov r15, QWORD PTR [rbp - 32]
    mov rbx, QWORD PTR [rbp - 40]
    mov rdi, QWORD PTR [rbp - 48]
    mov rsi, QWORD PTR [rbp - 56]
    add rsp, 4096
    pop rbp
    ret
EncryptPlayfair_ASM_Internal ENDP


; =================================================================================
; DecryptPlayfair_ASM_Internal (POPRAWIONA LOGIKA)
; =================================================================================
DecryptPlayfair_ASM_Internal PROC PUBLIC
    push rbp
    mov rbp, rsp
    sub rsp, 4096

    mov QWORD PTR [rbp - 8], r12
    mov QWORD PTR [rbp - 16], r13
    mov QWORD PTR [rbp - 24], r14
    mov QWORD PTR [rbp - 32], r15
    mov QWORD PTR [rbp - 40], rbx
    mov QWORD PTR [rbp - 48], rdi
    mov QWORD PTR [rbp - 56], rsi

    mov r12, rcx
    mov rsi, rdx
    mov rdi, r8
    mov r14, r9

    mov rcx, rsi
    call strlen_asm
    mov r15, rax

    xor r13, r13

DEC_PAIR_LOOP:
    cmp r13, r15
    jae DEC_DONE

    movzx eax, BYTE PTR [rsi + r13]
    movzx ecx, BYTE PTR [rsi + r13 + 1]

    movzx eax, BYTE PTR [r14 + rax]
    movzx ecx, BYTE PTR [r14 + rcx]

    ; --- Calc Row/Col 1 ---
    mov dl, 5
    div dl          ; AL=Row, AH=Col
    mov r8b, al     ; Store Row
    
    ; FIX A2218
    mov al, ah
    mov r9b, al     ; Store Col

    ; --- Calc Row/Col 2 ---
    mov eax, ecx
    mov dl, 5
    div dl          ; AL=Row, AH=Col
    mov r10b, al    ; Store Row

    ; FIX A2218
    mov al, ah
    mov r11b, al    ; Store Col

    ; --- Decrypt Logic ---
    cmp r8b, r10b
    je DEC_SAME_ROW
    cmp r9b, r11b
    je DEC_SAME_COL
    
    ; Rectangle
    mov al, r8b
    mov dl, 5
    mul dl
    add al, r11b
    mov r8b, al

    mov al, r10b
    mov dl, 5
    mul dl
    add al, r9b
    mov r9b, al
    jmp STORE_DEC

DEC_SAME_ROW:
    dec r9b
    jge CHECK_C2_DEC
    mov r9b, 4
CHECK_C2_DEC:
    dec r11b
    jge CALC_IDX_DEC_ROW
    mov r11b, 4
CALC_IDX_DEC_ROW:
    mov al, r8b
    mov dl, 5
    mul dl
    add al, r9b
    mov r8b, al

    mov al, r10b
    mov dl, 5
    mul dl
    add al, r11b
    mov r9b, al
    jmp STORE_DEC

DEC_SAME_COL:
    dec r8b
    jge CHECK_R2_DEC
    mov r8b, 4
CHECK_R2_DEC:
    dec r10b
    jge CALC_IDX_DEC_COL
    mov r10b, 4
CALC_IDX_DEC_COL:
    mov al, r8b
    mov dl, 5
    mul dl
    add al, r9b
    mov r8b, al

    mov al, r10b
    mov dl, 5
    mul dl
    add al, r11b
    mov r9b, al
    jmp STORE_DEC

STORE_DEC:
    movzx eax, r8b
    mov r8b, BYTE PTR [r12 + rax]
    movzx eax, r9b
    mov r9b, BYTE PTR [r12 + rax]

    mov BYTE PTR [rdi + r13], r8b
    mov BYTE PTR [rdi + r13 + 1], r9b

    add r13, 2
    jmp DEC_PAIR_LOOP

DEC_DONE:
    mov BYTE PTR [rdi + r13], 0

    mov r12, QWORD PTR [rbp - 8]
    mov r13, QWORD PTR [rbp - 16]
    mov r14, QWORD PTR [rbp - 24]
    mov r15, QWORD PTR [rbp - 32]
    mov rbx, QWORD PTR [rbp - 40]
    mov rdi, QWORD PTR [rbp - 48]
    mov rsi, QWORD PTR [rbp - 56]
    add rsp, 4096
    pop rbp
    ret
DecryptPlayfair_ASM_Internal ENDP

END