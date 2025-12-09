#pragma once

#ifdef PLAYFAIR_ASM_DLL_EXPORTS
#define PLAYFAIR_ASM_API __declspec(dllexport)
#else
#define PLAYFAIR_ASM_API __declspec(dllimport)
#endif

extern "C" {

    // Function 1: Build Key Table (Must match Playfair_C_API.h exactly)
    PLAYFAIR_ASM_API void BuildKeyTable_ASM(char* table, const char* key);

    // Function 2: Encrypt Text
    PLAYFAIR_ASM_API void EncryptPlayfair_ASM(const char* table, const char* plaintext, char* ciphertext);

    // Function 3: Decrypt Text
    PLAYFAIR_ASM_API void DecryptPlayfair_ASM(const char* table, const char* ciphertext, char* plaintext);
}