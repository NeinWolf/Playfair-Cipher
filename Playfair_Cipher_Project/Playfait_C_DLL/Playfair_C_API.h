#pragma once

#ifdef PLAYFAIR_C_DLL_EXPORTS
#define PLAYFAIR_C_API __declspec(dllexport)
#else
#define PLAYFAIR_C_API __declspec(dllimport)
#endif

// Defines the API for the C implementation (must match the ASM API)

extern "C" {

    // Function to generate the 5x5 key table
    // table: pointer to 5x5 char array (25 bytes)
    // key: C-string of the key
    PLAYFAIR_C_API void BuildKeyTable_C(char* table, const char* key);

    // Function to encrypt text
    // table: pointer to the 5x5 key table
    // plaintext: C-string input text
    // ciphertext: C-string output buffer (must be large enough)
    PLAYFAIR_C_API void EncryptPlayfair_C(const char* table, const char* plaintext, char* ciphertext);

    // Function to decrypt text
    // table: pointer to the 5x5 key table
    // ciphertext: C-string input text
    // plaintext: C-string output buffer (must be large enough)
    PLAYFAIR_C_API void DecryptPlayfair_C(const char* table, const char* ciphertext, char* plaintext);
}