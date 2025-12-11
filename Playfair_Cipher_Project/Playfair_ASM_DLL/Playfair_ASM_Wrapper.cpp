// =================================================================
// FILE: Playfair_ASM_Wrapper.cpp
// DESCRIPTION: Bridges C# and ASM. 
//              Crucially, it generates the Lookup Table (LUT) 
//              that the AVX2 code requires for fast indexing.
// =================================================================

#define PLAYFAIR_ASM_DLL_EXPORTS 
#include "Playfair_ASM_API.h"    
#include <cstring> // Required for memset

// --- Internal Assembly Prototypes ---
// We rename them here to avoid collision with the public exported functions.
// CRITICAL FIX: Added the 4th argument (index_lut) to match the ASM requirement (R9).

extern "C" void BuildKeyTable_ASM_Internal(char* table, const char* key);
extern "C" void EncryptPlayfair_ASM_Internal(const char* table, const char* plaintext, char* ciphertext, const char* index_lut);
extern "C" void DecryptPlayfair_ASM_Internal(const char* table, const char* ciphertext, char* plaintext, const char* index_lut);

// --- Helper: Build the 256-byte Lookup Table ---
// The ASM logic relies on 'vpshufb' to map ASCII chars to indices (0-24).
// Since vpshufb can't scan the 5x5 table itself, we pre-calculate this map.
void BuildIndexLUT(const char* table_5x5, char* lut_256) {
    // 1. Initialize with 0 or a safe default
    std::memset(lut_256, 0, 256);

    // 2. Scan the 5x5 table (25 bytes) to build the reverse map
    // ASCII 'A' (65) -> Index 0..24
    for (char i = 0; i < 25; i++) {
        unsigned char c = (unsigned char)table_5x5[i];
        lut_256[c] = i; // Map ASCII char 'c' to index 'i'
    }
}

// --- Public Exported Wrapper Functions (MATCHING API NAMES) ---

PLAYFAIR_ASM_API void BuildKeyTable_ASM(char* table, const char* key) {
    // No LUT needed for building the key
    BuildKeyTable_ASM_Internal(table, key);
}

PLAYFAIR_ASM_API void EncryptPlayfair_ASM(const char* table, const char* plaintext, char* ciphertext) {
    // 1. Create the Lookup Table on the stack (very fast)
    char index_lut[256];
    BuildIndexLUT(table, index_lut);

    // 2. Call ASM, passing the LUT as the 4th argument (Register R9)
    EncryptPlayfair_ASM_Internal(table, plaintext, ciphertext, index_lut);
}

PLAYFAIR_ASM_API void DecryptPlayfair_ASM(const char* table, const char* ciphertext, char* plaintext) {
    // 1. Create the Lookup Table
    char index_lut[256];
    BuildIndexLUT(table, index_lut);

    // 2. Call ASM, passing the LUT as the 4th argument (Register R9)
    DecryptPlayfair_ASM_Internal(table, ciphertext, plaintext, index_lut);
}