// =================================================================
// FILE: Playfair_ASM_Wrapper.cpp
// ...
// =================================================================

#define PLAYFAIR_ASM_DLL_EXPORTS 
#include "Playfair_ASM_API.h"    

// --- Prototypes for the actual Assembly routines (MUST BE UNIQUE) ---
// We rename them here to avoid collision with the public exported functions.

extern "C" void BuildKeyTable_ASM_Internal(char* table, const char* key);
extern "C" void EncryptPlayfair_ASM_Internal(const char* table, const char* plaintext, char* ciphertext);
extern "C" void DecryptPlayfair_ASM_Internal(const char* table, const char* ciphertext, char* plaintext);

// --- Public Exported Wrapper Functions (MATCHING API NAMES) ---
// These functions implement the public API and simply jump into the Assembly routines.

PLAYFAIR_ASM_API void BuildKeyTable_ASM(char* table, const char* key) {
    BuildKeyTable_ASM_Internal(table, key);
}

PLAYFAIR_ASM_API void EncryptPlayfair_ASM(const char* table, const char* plaintext, char* ciphertext) {
    EncryptPlayfair_ASM_Internal(table, plaintext, ciphertext);
}

PLAYFAIR_ASM_API void DecryptPlayfair_ASM(const char* table, const char* ciphertext, char* plaintext) {
    DecryptPlayfair_ASM_Internal(table, ciphertext, plaintext);
}