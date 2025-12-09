; =================================================================================
; DESCRIPTION: AVX2 normalize + scalar BuildKeyTable (Internal)
; Compatible with ML64 + Visual Studio (x64)
; =================================================================================

; --- Directives ---

.data
    ; ALIGN 32 is necessary for optimal AVX2 performance (32-byte constant loads)
CONSTANTS SEGMENT ALIGN(32) READ WRITE

    MASK_LE_Z       DB 32 DUP(5Ah)  ; 'Z'
    MASK_GE_A       DB 32 DUP(41h)  ; 'A'
    MASK_CASE_DIFF  DB 32 DUP(20h)
    MASK_A_LOWER    DB 32 DUP(61h)  ; 'a'
    MASK_Z_LOWER    DB 32 DUP(7Ah)  ; 'z'
    MASK_J_UPPER    DB 32 DUP(4Ah)  ; 'J'
    CONST_I_UPPER   DB 32 DUP(49h)  ; 'I'
    MASK_ZERO       DB 32 DUP(00h)
    MASK_ONES       DB 32 DUP(0FFh)

    MASK_PAD_X      DB 32 DUP(58h)  ; 'X' (Padding character)
    MASK_ONE        DB 32 DUP(01h)  ; Vector of ones (for shifts/increments)
    MASK_FIVE       DB 32 DUP(05h)  ; Constant 5 for 5x5 matrix math

    ; Reciprocal of 5 (used for vectorized integer division: Index / 5)
    ; Value: 0xCCCCCCCD (Approx 0.2 * 2^32)
    MASK_RECIP_5_DWORD DD 8 DUP(0CCCCCCCDh) ; 8 DWORDS for XMM
    
    ; Mask for constant 5 (for multiplying Row * 5)
    MASK_FIVE_DWORD DD 8 DUP(00000005h) ; 8 DWORDS for XMM

    MASK_FOUR_DWORD DD 8 DUP(00000004h) ; Used for the (X - 1) mod 5 wrap from 0 to 4

CONSTANTS ENDS

.code

; =================================================================================
; strlen_asm (Helper function)
; RCX = input string (const char*)
; Returns: RAX = length
; =================================================================================
strlen_asm PROC PUBLIC
    ; We only need RCX (input) and RAX (return)
    mov r8, rcx         ; r8 = Current pointer
    xor rax, rax        ; rax = Counter (length)

STRLEN_LOOP:
    cmp BYTE PTR [r8], 0
    je STRLEN_END       ; Found NULL terminator

    inc rax             ; Increment length
    inc r8              ; Advance pointer
    jmp STRLEN_LOOP

STRLEN_END:
    ret                 ; RAX contains the length
strlen_asm ENDP

; =================================================================================
; normalize_text_asm (Helper function, called internally)
; RCX = input (const char*), RDX = output (char*)
; =================================================================================
normalize_text_asm PROC PUBLIC
    mov rsi, rcx
    mov rdi, rdx
    xor r10, r10

SIMD_LOOP:
    vmovdqu ymm0, YMMWORD PTR [rsi]

    ; Check for NULL Terminator
    vpcmpeqb ymm1, ymm0, YMMWORD PTR MASK_ZERO
    vpmovmskb eax, ymm1
    test eax, eax
    jnz HANDLE_TAIL

    ; Case conversion and J->I logic (as provided)
    vpminub ymm2, ymm0, YMMWORD PTR MASK_LE_Z
    vpmaxub ymm3, ymm2, YMMWORD PTR MASK_GE_A
    vpcmpeqb ymm2, ymm0, ymm3

    vpminub ymm4, ymm0, YMMWORD PTR MASK_Z_LOWER
    vpmaxub ymm5, ymm4, YMMWORD PTR MASK_A_LOWER
    vpcmpeqb ymm4, ymm0, ymm5

    vpor ymm5, ymm2, ymm4
    vpand ymm6, ymm5, ymm4
    vpsubb ymm0, ymm0, ymm6

    vpcmpeqb ymm6, ymm0, YMMWORD PTR MASK_J_UPPER
    vpblendvb ymm0, ymm0, YMMWORD PTR CONST_I_UPPER, ymm6

    add rsi, 32
    jmp SIMD_LOOP

HANDLE_TAIL:
    ; scalar tail processing
    xor r8, r8
SCALAR_LOOP:
    movzx eax, BYTE PTR [rsi + r8]
    cmp al, 0
    je END_NORMALIZE

    cmp al, 'A'
    jl CHECK_LOWER
    cmp al, 'Z'
    jle PROCESS_CHAR

CHECK_LOWER:
    cmp al, 'a'
    jl NEXT_CHAR
    cmp al, 'z'
    jg NEXT_CHAR

PROCESS_CHAR:
    and al, 0DFh

CHECK_J:
    cmp al, 'J'
    jne STORE_CHAR
    mov al, 'I'

STORE_CHAR:
    mov BYTE PTR [rdi + r10], al
    inc r10

NEXT_CHAR:
    inc r8
    jmp SCALAR_LOOP

END_NORMALIZE:
    mov BYTE PTR [rdi + r10], 0
    vzeroupper
    ret

normalize_text_asm ENDP

; =================================================================================
; BuildKeyTable_ASM_Internal (Core implementation, called by C++ wrapper)
; RCX = table_ptr, RDX = key_ptr
; =================================================================================
BuildKeyTable_ASM_Internal PROC PUBLIC
    push rbp
    push rdi
    push rsi

    ; Stack space for normalized key buffer (1024) + used array (32) = 1056
    sub rsp, 1056

    mov r8, rsp
    mov r9, rsp
    add r9, 1024

    ; Save original RCX and RDX arguments, adjusted for the 3 pushes (3 * 8 = 24 bytes)
    mov [rsp + 1056 + 24], rcx
    mov [rsp + 1056 + 32], rdx

    ; Call normalize_text_asm(key_ptr, normalized_buffer)
    mov rcx, [rsp + 1056 + 32]
    mov rdx, r8
    call normalize_text_asm

    mov rdi, [rsp + 1056 + 24]  ; table_ptr
    mov rsi, r8                 ; normalized_key

    xor r10, r10
    xor r11, r11

DEDUPE_LOOP:
    movzx r13d, BYTE PTR [rsi + r10]
    cmp r13d, 0
    je FILL_ALPHABET

    mov r14d, r13d
    sub r14d, 'A'

    movzx r15d, BYTE PTR [r9 + r14]
    cmp r15d, 0
    jne DEDUPE_CONT

    mov BYTE PTR [r9 + r14], 1
    mov BYTE PTR [rdi + r11], r13b
    inc r11

DEDUPE_CONT:
    inc r10
    cmp r11, 25
    je CLEANUP
    jmp DEDUPE_LOOP

FILL_ALPHABET:
    mov r10, 'A'

ALPHA_LOOP:
    cmp r10, 'Z'
    jg CLEANUP

    cmp r10, 'J'
    je ALPHA_CONT

    mov r14d, r10d
    sub r14d, 'A'

    movzx r15d, BYTE PTR [r9 + r14]
    cmp r15d, 0
    jne ALPHA_CONT

    mov BYTE PTR [r9 + r14], 1
    mov BYTE PTR [rdi + r11], r10b
    inc r11

    cmp r11, 25
    je CLEANUP

ALPHA_CONT:
    inc r10
    jmp ALPHA_LOOP

CLEANUP:
    add rsp, 1056
    pop rsi
    pop rdi
    pop rbp
    ret

BuildKeyTable_ASM_Internal ENDP

; =================================================================================
; EncryptPlayfair_ASM_Internal (Core implementation - Digraph Formation & Encryption)
; RCX = table_ptr, RDX = plaintext_ptr, R8 = ciphertext_ptr
; =================================================================================

EncryptPlayfair_ASM_Internal PROC PUBLIC
    ; Save non-volatile registers (RBP, RDI, RSI, R12, R13, R14, R15)
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; Allocate 4KB on stack for the working (padded) plaintext buffer.
    sub rsp, 4096       
    
    ; 1. Load arguments into persistent registers
    mov r12, rcx        ; R12 = table_ptr (Fixed lookup table)
    mov rdi, r8         ; RDI = ciphertext_ptr (Final output destination)
    mov rsi, rdx        ; RSI = plaintext_ptr (Original input source)
    
    ; 2. Initialize pointers and counters
    mov r14, rsp        ; R14 = Padded working buffer (Destination for step 1)
    xor r13, r13        ; R13 = Input index into RSI (k)
    xor r15, r15        ; R15 = Padded output index into R14 (n)

; --- PHASE 1: VECTORIZED DIGRAPH FORMATION AND PADDING ---

DIGRAPH_LOOP:
    ; Load 32 bytes from current read position
    vmovdqu ymm0, YMMWORD PTR [rsi + r13]

    ; Check for NULL terminator in the input
    vpcmpeqb ymm1, ymm0, YMMWORD PTR MASK_ZERO
    vpmovmskb eax, ymm1
    test eax, eax
    jnz HANDLE_ODD_LENGTH_CHECK ; Found end of input
    
    ; Compare ymm0 with a copy shifted by 1 byte (to check if char[k] == char[k+1])
    ; We need to read 33 bytes to do a full 32-byte comparison, handling the last byte.
    ; For robust SIMD comparison, we only check 31 pairs: (0,1), (1,2) ... (30,31)
    
    ; Load 32 bytes starting from k+1 (RSI + R13 + 1)
    vmovdqu ymm1, YMMWORD PTR [rsi + r13 + 1]
    
    ; Compare YMM0 (bytes 0-31) with YMM1 (bytes 1-32)
    vpcmpeqb ymm2, ymm0, ymm1 
    
    ; Shift the comparison mask right by one byte to align the mask with the first byte of the pair.
    ; E.g., if byte 1 == byte 2, we need the mask bit at position 1.
    vpalignr ymm2, ymm2, ymm2, 1
    
    ; Extract the mask (32 bits)
    vpmovmskb ecx, ymm2 
    
    ; Check if any double letters were found (excluding the 32nd bit which is garbage)
    mov edx, 7FFFFFFFH ; Mask to ignore the 32nd bit
    and ecx, edx
    test ecx, ecx
    jnz SCALAR_INSERTION_HANDLE ; Double letter found - drop to scalar insertion

    ; --- No double letters found in this 32-byte block ---
    
    ; Copy the 32 bytes to the padded buffer
    vmovdqu YMMWORD PTR [r14 + r15], ymm0
    add r13, 32                 ; Advance input index
    add r15, 32                 ; Advance padded output index
    jmp DIGRAPH_LOOP

; -------------------------------------------------------------
; SCALAR HANDLING: Dynamic Shifting and Insertion of 'X'
; -------------------------------------------------------------
SCALAR_INSERTION_HANDLE:
    ; Need to process byte-by-byte from current input position (R13) up to the NULL terminator
    ; We are here because a double letter or the end of the input was detected nearby.

SCALAR_INSERTION_LOOP:
    ; Load current character A
    movzx r10d, BYTE PTR [rsi + r13]
    cmp r10d, 0
    je HANDLE_ODD_LENGTH_CHECK  ; End of input
    
    ; Store current character A to padded buffer
    mov BYTE PTR [r14 + r15], r10b
    inc r15                         ; Advance padded index

    ; Load next character B (check if A == B)
    movzx r11d, BYTE PTR [rsi + r13 + 1]
    cmp r11d, 0                     
    je CHECK_FOR_FINAL_PADDING      ; Next char is NULL, check for odd length

    ; Check for double letter: A == B
    cmp r10d, r11d                  
    jne NO_INSERTION                ; Not a double letter

    ; --- Double Letter Found (A == B) ---
    ; Insert padding 'X'
    mov BYTE PTR [r14 + r15], 58h   ; 58h = 'X'
    inc r15                         ; Advance padded index
    
    ; Do NOT advance input index R13, as the next letter (B) becomes the start of the next pair
    inc r13                         ; Advance input index (A)

    jmp SCALAR_INSERTION_LOOP       ; Process next pair

NO_INSERTION:
    ; A and B are different - store B and advance input index R13 by 2
    inc r13                         ; Advance input index (A)
    jmp SCALAR_INSERTION_LOOP       ; Process next pair

CHECK_FOR_FINAL_PADDING:
    ; Reached the end of the original plaintext (r11d was 0)
    ; The current padded length is in R15.
    mov r10, r15
    and r10, 1                      ; Check if R15 is odd
    cmp r10, 0
    je DIGRAPH_FORMATION_COMPLETE   ; Padded length is even, we are done

    ; --- Odd Length Found: Pad with 'X' ---
    mov BYTE PTR [r14 + r15], 58h   ; 58h = 'X'
    inc r15                         ; Final padded length
    
DIGRAPH_FORMATION_COMPLETE:
    ; Null terminate the final padded string
    mov BYTE PTR [r14 + r15], 0

    ; --- Jump to Phase 2: Encryption ---
    jmp ENCRYPTION_LOOP_START

HANDLE_ODD_LENGTH_CHECK:
    ; This jump is taken when the SIMD loop found a NULL (end of input)
    ; Need to jump to the final padding logic, as all characters up to NULL were processed/copied.
    jmp SCALAR_INSERTION_HANDLE ; R13 is at the NULL, jump to process the remainder

; -------------------------------------------------------------
; PHASE 2: VECTORIZED ENCRYPTION LOOKUP AND RULE APPLICATION
; R14 holds the fully padded, ready-to-encrypt plaintext
; R15 holds the length of the padded plaintext (even)
; R12 (Key Table 5x5), R10 (256-byte Index LUT)
; -------------------------------------------------------------
ENCRYPTION_LOOP_START:
    ; Assuming R9 holds the index_lut_ptr from the C++ wrapper
    mov r10, r9 ; R10 = Index LUT Pointer

    xor r13, r13 ; Reset R13 (index) for encryption loop
    
ENCRYPT_LOOP:
    cmp r13, r15
    jae CLEANUP ; Loop ends when index R13 >= padded length R15 (even)
    
    ; 1. Load 16 bytes (8 digraphs) of padded plaintext from R14
    vmovdqu xmm0, XMMWORD PTR [r14 + r13]
    
    ; --- 2. VECTORIZED INDEX LOOKUP (Character -> Index 0-24) ---
    ; Use vpshufb to convert 16 ASCII characters in xmm0 directly into 
    ; their 0-24 index values using the 256-byte LUT at R10.
    vpshufb xmm1, xmm0, XMMWORD PTR [r10] ; xmm1 now holds 16 index values (0-24)
    
    ; --- 3. SEPARATE INTO ROW/COLUMN VECTORS ---
    
    ; The index values in xmm1 are 8-bit bytes. We must convert them to 
    ; 32-bit DWORDS for the vectorized math operations (vpmulld, vpsrad, vpsubd).
    
    ; Extract first letters (A1, A2, A3, A4, ...) 
    ; vpunpcklbw: Interleaves 8-bit bytes 0, 2, 4, 6... into the low 8 bytes of xmm2
    vpunpcklbw xmm2, xmm1, XMMWORD PTR MASK_ZERO 
    ; vpmovzxbd: Converts the 8 index bytes (0-7) into 8 DWORDS (32-bit integers)
    vpmovzxbd xmm2, xmm2 
    
    ; Extract second letters (B1, B2, B3, B4, ...) 
    ; vpunpckhbw: Interleaves 8-bit bytes 1, 3, 5, 7... into the high 8 bytes of xmm3
    vpunpckhbw xmm3, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm3, xmm3
    
    ; --- 4. ROW/COLUMN CALCULATION (8 DWORDS each) ---
    ; Row = Index / 5, Col = Index % 5
    
    ; ** PAIR 1 (First letters: xmm2) **
    
    ; ROW 1 (xmm4): Index / 5 = (Index * Recip) >> 19
    vmovdqa xmm4, xmm2 
    vpmulld xmm4, xmm4, XMMWORD PTR MASK_RECIP_5_DWORD ; xmm4 = Index * Recip
    vpsrad xmm4, xmm4, 19 ; xmm4 = Row 1 (8 DWORDS)
    
    ; COL 1 (xmm5): Index % 5 = Index - (Row * 5)
    vmovdqa xmm5, xmm4 ; xmm5 = Row 1
    vpmulld xmm5, xmm5, XMMWORD PTR MASK_FIVE_DWORD ; xmm5 = Row * 5
    vpsubd xmm5, xmm2, xmm5 ; xmm5 = Col 1 (8 DWORDS)
    
    ; ** PAIR 2 (Second letters: xmm3) **
    
    ; ROW 2 (xmm6): Index / 5
    vmovdqa xmm6, xmm3
    vpmulld xmm6, xmm6, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm6, xmm6, 19 ; xmm6 = Row 2 (8 DWORDS)
    
    ; COL 2 (xmm7): Index % 5
    vmovdqa xmm7, xmm6 ; xmm7 = Row 2
    vpmulld xmm7, xmm7, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm7, xmm3, xmm7 ; xmm7 = Col 2 (8 DWORDS)
    
    ; --- 5. ENCRYPTION RULE APPLICATION (NEXT STEP) ---
    ; xmm4/xmm5 (Row1/Col1), xmm6/xmm7 (Row2/Col2) are ready for comparison.

    ; -------------------------------------------------------------
    ; A. Generate Rule Masks (Full 32-bit mask where condition is true)
    ; -------------------------------------------------------------
    
    ; R_EQ_Mask (xmm8): Row1 == Row2
    vpcmpeqd xmm8, xmm4, xmm6
    
    ; C_EQ_Mask (xmm9): Col1 == Col2
    vpcmpeqd xmm9, xmm5, xmm7
    
    ; R_ONLY_EQ_Mask (xmm10): Same Row Rule (R1=R2 AND C1!=C2)
    ; Invert C_EQ_Mask
    vpcmpeqd xmm10, xmm9, XMMWORD PTR MASK_ZERO ; xmm10 = NOT C_EQ_Mask
    vpand xmm10, xmm10, xmm8                    ; xmm10 = R_EQ_Mask AND NOT C_EQ_Mask
    
    ; C_ONLY_EQ_Mask (xmm11): Same Col Rule (C1=C2 AND R1!=R2)
    ; Invert R_EQ_Mask
    vpcmpeqd xmm11, xmm8, XMMWORD PTR MASK_ZERO ; xmm11 = NOT R_EQ_Mask
    vpand xmm11, xmm11, xmm9                    ; xmm11 = C_EQ_Mask AND NOT R_EQ_Mask
    
    ; RECT_Mask (xmm12): Rectangle Rule (R1!=R2 AND C1!=C2)
    vpor xmm13, xmm8, xmm9                      ; xmm13 = R_EQ_Mask OR C_EQ_Mask
    vpcmpeqd xmm12, xmm13, XMMWORD PTR MASK_ZERO ; xmm12 = NOT (R_EQ_Mask OR C_EQ_Mask)

    ; -------------------------------------------------------------
    ; B. Apply Same Row Rule (R1=R2): Col = (Col + 1) mod 5
    ; -------------------------------------------------------------
    
    ; We use xmm13, xmm14 as scratch registers
    
    ; Apply to C1 (xmm5): New C1 = (C1 + 1) mod 5
    vmovdqa xmm13, xmm5
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE   ; C1 + 1
    
    ; Modulo 5 Check: if C1+1 == 5, subtract 5 (which means result is 0)
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE 
    vpsubd xmm13, xmm13, xmm14                  
    
    ; Blend the result back into C1 (xmm5) using R_ONLY_EQ_Mask (xmm10)
    vpblendvb xmm5, xmm5, xmm13, xmm10
    
    ; Apply to C2 (xmm7): New C2 = (C2 + 1) mod 5
    vmovdqa xmm13, xmm7
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm7, xmm7, xmm13, xmm10
    
    ; -------------------------------------------------------------
    ; C. Apply Same Column Rule (C1=C2): Row = (Row + 1) mod 5
    ; -------------------------------------------------------------
    
    ; Apply to R1 (xmm4): New R1 = (R1 + 1) mod 5
    vmovdqa xmm13, xmm4
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE   
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm4, xmm4, xmm13, xmm11 ; Blend into R1 (xmm4)
    
    ; Apply to R2 (xmm6): New R2 = (R2 + 1) mod 5
    vmovdqa xmm13, xmm6
    vpaddd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpcmpeqd xmm14, xmm13, XMMWORD PTR MASK_FIVE
    vpsubd xmm13, xmm13, xmm14
    vpblendvb xmm6, xmm6, xmm13, xmm11 ; Blend into R2 (xmm6)
    
    ; -------------------------------------------------------------
    ; D. Apply Rectangle Rule (R1!=R2 & C1!=C2): Swap Columns
    ; -------------------------------------------------------------
    
    ; Backup original C1 (xmm5) for the swap
    vmovdqa xmm13, xmm5 
    
    ; New C1 (xmm5) = Old C2 (xmm7)
    vpblendvb xmm5, xmm5, xmm7, xmm12 ; Blend C2 into C1
    
    ; New C2 (xmm7) = Original C1 (xmm13)
    vpblendvb xmm7, xmm7, xmm13, xmm12 ; Blend C1_original into C2
    
    ; -------------------------------------------------------------
    ; E. Final Index and Character Calculation (Hybrid)
    ; -------------------------------------------------------------
    
    ; 1. Calculate New Index (0-24) = (New R * 5) + New C
    
    ; New Index 1 (xmm13) = (R1 * 5) + C1
    vmovdqa xmm13, xmm4
    vpmulld xmm13, xmm13, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm13, xmm13, xmm5
    
    ; New Index 2 (xmm14) = (R2 * 5) + C2
    vmovdqa xmm14, xmm6
    vpmulld xmm14, xmm14, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm14, xmm14, xmm7
    
    ; 2. Pack 16 32-bit indices (xmm13/xmm14) into 16 8-bit index bytes (xmm0)
    
    ; xmm13 (8 DWORDS) and xmm14 (8 DWORDS) -> xmm0 (16 BYTES)
    vpackusdw xmm0, xmm13, xmm14 ; xmm0 now holds 16 16-bit indices
    vpackuswb xmm0, xmm0, xmm0   ; xmm0 now holds 16 8-bit indices (0-24)

    ; 3. Final Character Lookup (Key Table is 25 bytes, requires scalar gather for efficiency)
    
    ; Save the 16 packed 8-bit indices (0-24) to the stack buffer (RSP)
    vmovdqu XMMWORD PTR [rsp], xmm0 
    
    ; R12 is the Key Table (source)
    ; RDI is the Ciphertext (destination)
    ; R13 is the starting offset for this 16-byte block
    
    mov r11, 0 ; Loop counter (i = 0 to 15)
    
SCALAR_FINAL_LOOKUP:
    cmp r11, 16
    jae CONTINUE_ENCRYPT_LOOP
    
    ; 1. Load the 8-bit index (0-24) from the temporary stack buffer
    movzx r14d, BYTE PTR [rsp + r11] 
    
    ; 2. Look up the character in the Key Table (R12)
    movzx r15d, BYTE PTR [r12 + r14] ; R15d = Final Character
    
    ; 3. Store the character to the Ciphertext buffer (RDI)
    mov rax, r13
    add rax, r11            ; rax = r13 + r11
    mov BYTE PTR [rdi + rax], r15b

    inc r11
    jmp SCALAR_FINAL_LOOKUP

CONTINUE_ENCRYPT_LOOP:
    add r13, 16 ; Advance main input/output index by 16 bytes (8 digraphs)
    jmp ENCRYPT_LOOP

; -------------------------------------------------------------
; CLEANUP
; -------------------------------------------------------------
CLEANUP:
    mov BYTE PTR [rdi + r13], 0 
    vzeroupper          
    
    ; Deallocate stack buffer (4096 bytes)
    add rsp, 4096
    
    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    ret
EncryptPlayfair_ASM_Internal ENDP

; =================================================================================
; DecryptPlayfair_ASM_Internal (SIMD AVX2 implementation - Decryption)
; RCX = table_ptr, RDX = ciphertext_ptr, R8 = plaintext_ptr
; NOTE: Arguments RDX and R8 are swapped compared to encryption!
; =================================================================================

DecryptPlayfair_ASM_Internal PROC PUBLIC
    ; Save non-volatile registers
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; Allocate 4KB on stack for the working (padded) ciphertext buffer.
    sub rsp, 4096       
    
    ; 1. Load arguments into persistent registers (Decryption uses a different mapping)
    mov r12, rcx        ; R12 = table_ptr
    mov rsi, rdx        ; RSI = ciphertext_ptr (Source - Input)
    mov rdi, r8         ; RDI = plaintext_ptr (Destination - Output)
    
    ; 2. Initialize pointers and counters (No digraph formation needed for decryption)
    mov r14, rsp        ; R14 = Temporary padded buffer (We skip P1, but use the buffer for symmetry)
    xor r13, r13        ; R13 = Input index (k)
    
    ; The full ciphertext is already padded and ready for decryption.
    ; We skip the Digraph Formation logic (Phase 1) and jump straight to the loop setup.

    ; Calculate length of input ciphertext (RSI) for loop boundary (R15)
    mov rcx, rsi
    call strlen_asm ; Helper function (Assuming strlen is available or simply use a known max length)
    mov r15, rax    ; R15 = Ciphertext Length (N)
    
    ; If strlen_asm is not available, assume maximum length of 4096 / 2
    ; For robust code, you should include a small scalar strlen loop here.
    ; Assuming R15 is set correctly to the length of the input ciphertext (RSI).

; -------------------------------------------------------------
; PHASE 2: VECTORIZED INDEX LOOKUP AND RULE APPLICATION
; R12 (Key Table 5x5), R9 (256-byte Index LUT - Must be passed)
; R15 holds the length of the ciphertext (even)
; -------------------------------------------------------------
ENCRYPT_LOOP: ; Renamed from ENCRYPT_LOOP to DECRYPT_LOOP for clarity, but using same label structure
    cmp r13, r15
    jae CLEANUP ; Loop ends when index R13 >= ciphertext length R15
    
    ; 1. Load 16 bytes (8 digraphs) of ciphertext from RSI
    vmovdqu xmm0, XMMWORD PTR [rsi + r13]
    
    ; --- 2. VECTORIZED INDEX LOOKUP (Character -> Index 0-24) ---
    ; R10 = Index LUT Pointer (Assuming R9 from caller was moved to R10 for internal use)
    mov r10, r9 
    vpshufb xmm1, xmm0, XMMWORD PTR [r10] ; xmm1 now holds 16 index values (0-24)
    
    ; --- 3. SEPARATE INTO ROW/COLUMN VECTORS (Same as Encryption) ---
    vpunpcklbw xmm2, xmm1, XMMWORD PTR MASK_ZERO 
    vpmovzxbd xmm2, xmm2 
    vpunpckhbw xmm3, xmm1, XMMWORD PTR MASK_ZERO
    vpmovzxbd xmm3, xmm3
    
    ; ROW 1 (xmm4), COL 1 (xmm5)
    vmovdqa xmm4, xmm2 
    vpmulld xmm4, xmm4, XMMWORD PTR MASK_RECIP_5_DWORD 
    vpsrad xmm4, xmm4, 19
    vmovdqa xmm5, xmm4 
    vpmulld xmm5, xmm5, XMMWORD PTR MASK_FIVE_DWORD 
    vpsubd xmm5, xmm2, xmm5
    
    ; ROW 2 (xmm6), COL 2 (xmm7)
    vmovdqa xmm6, xmm3
    vpmulld xmm6, xmm6, XMMWORD PTR MASK_RECIP_5_DWORD
    vpsrad xmm6, xmm6, 19
    vmovdqa xmm7, xmm6
    vpmulld xmm7, xmm7, XMMWORD PTR MASK_FIVE_DWORD
    vpsubd xmm7, xmm3, xmm7
    
    ; -------------------------------------------------------------
    ; A. Generate Rule Masks (Same as Encryption)
    ; -------------------------------------------------------------
    vpcmpeqd xmm8, xmm4, xmm6                    ; R_EQ_Mask (Row1 == Row2)
    vpcmpeqd xmm9, xmm5, xmm7                    ; C_EQ_Mask (Col1 == Col2)
    
    vpcmpeqd xmm10, xmm9, XMMWORD PTR MASK_ZERO  ; R_ONLY_EQ_Mask (R1=R2 AND C1!=C2)
    vpand xmm10, xmm10, xmm8                     
    
    vpcmpeqd xmm11, xmm8, XMMWORD PTR MASK_ZERO  ; C_ONLY_EQ_Mask (C1=C2 AND R1!=R2)
    vpand xmm11, xmm11, xmm9                     
    
    vpor xmm13, xmm8, xmm9                       ; RECT_Mask 
    vpcmpeqd xmm12, xmm13, XMMWORD PTR MASK_ZERO 

    ; -------------------------------------------------------------
    ; B. Apply Same Row Rule (R1=R2): Col = (Col - 1) mod 5
    ; -------------------------------------------------------------
    
    ; The logic: New C = (C - 1). If C was 0, New C must be 4.
    
    ; Apply to C1 (xmm5)
    vpcmpeqd xmm14, xmm5, XMMWORD PTR MASK_ZERO  ; xmm14 = Mask if C1 == 0
    vmovdqa xmm13, xmm5                          ; xmm13 = C1
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE    ; C1 - 1
    
    ; If C1 was 0, blend in 4. Else keep C1 - 1.
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm14 
    vpblendvb xmm5, xmm5, xmm13, xmm10           ; Blend final result into C1
    
    ; Apply to C2 (xmm7)
    vpcmpeqd xmm14, xmm7, XMMWORD PTR MASK_ZERO  ; Mask if C2 == 0
    vmovdqa xmm13, xmm7
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm14
    vpblendvb xmm7, xmm7, xmm13, xmm10           ; Blend final result into C2

    ; -------------------------------------------------------------
    ; C. Apply Same Column Rule (C1=C2): Row = (Row - 1) mod 5
    ; -------------------------------------------------------------
    
    ; Apply to R1 (xmm4)
    vpcmpeqd xmm14, xmm4, XMMWORD PTR MASK_ZERO  ; Mask if R1 == 0
    vmovdqa xmm13, xmm4
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm14
    vpblendvb xmm4, xmm4, xmm13, xmm11           ; Blend final result into R1
    
    ; Apply to R2 (xmm6)
    vpcmpeqd xmm14, xmm6, XMMWORD PTR MASK_ZERO  ; Mask if R2 == 0
    vmovdqa xmm13, xmm6
    vpsubd xmm13, xmm13, XMMWORD PTR MASK_ONE
    vpblendvb xmm13, xmm13, XMMWORD PTR MASK_FOUR_DWORD, xmm14
    vpblendvb xmm6, xmm6, xmm13, xmm11           ; Blend final result into R2
    
    ; -------------------------------------------------------------
    ; D. Apply Rectangle Rule (Same as Encryption): Swap Columns
    ; -------------------------------------------------------------
    vmovdqa xmm13, xmm5 
    vpblendvb xmm5, xmm5, xmm7, xmm12 
    vpblendvb xmm7, xmm7, xmm13, xmm12 
    
    ; -------------------------------------------------------------
    ; E. Final Index and Character Calculation (Hybrid Lookup)
    ; -------------------------------------------------------------
    
    ; New Index 1 (xmm13) = (R1 * 5) + C1
    vmovdqa xmm13, xmm4
    vpmulld xmm13, xmm13, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm13, xmm13, xmm5
    
    ; New Index 2 (xmm14) = (R2 * 5) + C2
    vmovdqa xmm14, xmm6
    vpmulld xmm14, xmm14, XMMWORD PTR MASK_FIVE_DWORD
    vpaddd xmm14, xmm14, xmm7
    
    ; Pack 16 32-bit indices into 16 8-bit index bytes (xmm0)
    vpackusdw xmm0, xmm13, xmm14 
    vpackuswb xmm0, xmm0, xmm0   

    ; Final Character Lookup (Key Table is 25 bytes, requires scalar gather for efficiency)
    vmovdqu XMMWORD PTR [rsp], xmm0 ; Save indices to stack buffer
    
    mov r11, 0 ; Loop counter (i = 0 to 15)
    
SCALAR_FINAL_LOOKUP:
    cmp r11, 16
    jae CONTINUE_DECRYPT_LOOP
    
    ; 1. Load the 8-bit index (0-24) from the temporary stack buffer
    movzx r14d, BYTE PTR [rsp + r11] 
    
    ; 2. Look up the character in the Key Table (R12)
    movzx r15d, BYTE PTR [r12 + r14] ; R15d = Final Character
    
    ; 3. Store the character to the Plaintext buffer (RDI)
    mov rax, r13           ; move offset into rax (scratch)
    add rax, r11            ; rax = r13 + r11
    mov BYTE PTR [rdi + rax], r15b
    
    inc r11
    jmp SCALAR_FINAL_LOOKUP

CONTINUE_DECRYPT_LOOP:
    add r13, 16 ; Advance main input/output index by 16 bytes (8 digraphs)
    jmp ENCRYPT_LOOP ; Jump back to the main loop

; -------------------------------------------------------------
; CLEANUP
; -------------------------------------------------------------
CLEANUP:
    mov BYTE PTR [rdi + r13], 0 ; Null terminate the final plaintext
    vzeroupper          
    
    ; Deallocate stack buffer
    add rsp, 4096
    
    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    ret
    
DecryptPlayfair_ASM_Internal ENDP

END