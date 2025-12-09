// ==================================================================================
// FILE: Playfair_C_Impl.cpp
// PROJECT: Playfair_C_DLL (High-Level Reference Implementation)
// DESCRIPTION: Contains the static implementation of the Playfair Cipher 
//              and the public wrappers for DLL export.
// ==================================================================================

#define PLAYFAIR_C_DLL_EXPORTS // Required for this project to export the functions

#include "Playfair_C_API.h"
#include <string.h>
#include <ctype.h>
// Note: <stdio.h> is not needed here as there is no printing/console I/O
// Note: MAX_TEXT_LEN is defined below, or ideally, in a common header.

#define MAX_TEXT_LEN 1024

/* ==================== STATIC UTILITY FUNCTIONS ==================== */

// Converts to uppercase, removes non-letters, replaces J with I
static void normalize_text(const char* input, char* output) {
    int k = 0;
    for (int i = 0; input[i] != '\0'; i++) {
        if (isalpha((unsigned char)input[i])) {
            char c = toupper((unsigned char)input[i]);
            if (c == 'J') c = 'I';
            output[k++] = c;
        }
    }
    output[k] = '\0';
}

/* ==================== STATIC KEY TABLE GENERATION ==================== */

// Builds 5x5 key table from key string
static void build_key_table(const char* key, char table[5][5]) {
    int used[26] = { 0 };
    char normalized_key[MAX_TEXT_LEN];
    int k = 0;

    // Normalizes key (only letters, uppercase, J->I)
    normalize_text(key, normalized_key);

    // Fills from key first
    for (int i = 0; normalized_key[i] != '\0'; i++) {
        char c = normalized_key[i];
        int idx = c - 'A';
        if (c == 'J') idx = 'I' - 'A'; // J is treated as I for indexing
        if (!used[idx]) {
            used[idx] = 1;
            normalized_key[k++] = c;
        }
    }

    // Adds remaining letters A-Z (skips J)
    for (char c = 'A'; c <= 'Z'; c++) {
        if (c == 'J') continue;
        int idx = c - 'A';
        if (!used[idx]) {
            used[idx] = 1;
            normalized_key[k++] = c;
        }
    }
    normalized_key[k] = '\0';

    // Fills 5x5 table
    int pos = 0;
    for (int row = 0; row < 5; row++) {
        for (int col = 0; col < 5; col++) {
            table[row][col] = normalized_key[pos++];
        }
    }
}

// Finds row and column of character 'ch' in table
static void find_position(char table[5][5], char ch, int* row, int* col) {
    if (ch == 'J') ch = 'I';
    for (int r = 0; r < 5; r++) {
        for (int c = 0; c < 5; c++) {
            if (table[r][c] == ch) {
                *row = r;
                *col = c;
                return;
            }
        }
    }
}

/* ==================== STATIC PLAINTEXT PREPARATION ==================== */

// Prepares plaintext into digraphs: removes non-letters, splits into pairs,
static void prepare_plaintext(const char* input, char* output) {
    char normalized[MAX_TEXT_LEN];
    normalize_text(input, normalized);

    int len = strlen(normalized);
    int i = 0, k = 0;

    while (i < len) {
        char first = normalized[i];
        char second;

        if (i + 1 < len) {
            second = normalized[i + 1];
            if (first == second) {
                second = 'X'; // Pad with 'X'
                i += 1;
            }
            else {
                i += 2;
            }
        }
        else {
            second = 'X'; // Pad last character
            i += 1;
        }

        output[k++] = first;
        output[k++] = second;
    }
    output[k] = '\0';
}

/* ==================== STATIC ENCRYPTION / DECRYPTION ==================== */

static void encrypt_playfair(char table[5][5], const char* plaintext, char* ciphertext) {
    char prepared[MAX_TEXT_LEN];
    prepare_plaintext(plaintext, prepared);

    int len = strlen(prepared);
    int k = 0;

    for (int i = 0; i < len; i += 2) {
        char a = prepared[i];
        char b = prepared[i + 1];

        int r1, c1, r2, c2;
        find_position(table, a, &r1, &c1);
        find_position(table, b, &r2, &c2);

        if (r1 == r2) {
            // Same row: shift right (encrypt)
            ciphertext[k++] = table[r1][(c1 + 1) % 5];
            ciphertext[k++] = table[r2][(c2 + 1) % 5];
        }
        else if (c1 == c2) {
            // Same column: shift down (encrypt)
            ciphertext[k++] = table[(r1 + 1) % 5][c1];
            ciphertext[k++] = table[(r2 + 1) % 5][c2];
        }
        else {
            // Rectangle: swap columns
            ciphertext[k++] = table[r1][c2];
            ciphertext[k++] = table[r2][c1];
        }
    }
    ciphertext[k] = '\0';
}

static void decrypt_playfair(char table[5][5], const char* ciphertext, char* plaintext) {
    int len = strlen(ciphertext);
    int k = 0;

    for (int i = 0; i < len; i += 2) {
        char a = toupper((unsigned char)ciphertext[i]);
        char b = toupper((unsigned char)ciphertext[i + 1]);

        // Note: The C code already handles J->I in find_position, but let's 
        // ensure the input cipher text is normalized if it came from a source 
        // that didn't enforce A-Z. The original code included this normalization:
        if (a == 'J') a = 'I';
        if (b == 'J') b = 'I';

        int r1, c1, r2, c2;
        find_position(table, a, &r1, &c1);
        find_position(table, b, &r2, &c2);

        if (r1 == r2) {
            // Same row: shift left (decrypt)
            plaintext[k++] = table[r1][(c1 + 4) % 5]; // +4 is equivalent to -1 mod 5
            plaintext[k++] = table[r2][(c2 + 4) % 5];
        }
        else if (c1 == c2) {
            // Same column: shift up (decrypt)
            plaintext[k++] = table[(r1 + 4) % 5][c1];
            plaintext[k++] = table[(r2 + 4) % 5][c2];
        }
        else {
            // Rectangle: swap columns (same for decrypt)
            plaintext[k++] = table[r1][c2];
            plaintext[k++] = table[r2][c1];
        }
    }
    plaintext[k] = '\0';
}

/* ==================== PUBLIC DLL EXPORT WRAPPERS ==================== */

// Cast helper macro (since the DLL receives a 1D pointer to the 5x5 table)
#define CAST_TABLE(ptr) ((char(*)[5])ptr)

// Function 1: Build Key Table
PLAYFAIR_C_API void BuildKeyTable_C(char* table_ptr, const char* key) {
    // Cast the flat pointer (char*) back to a 2D array (char(*)[5])
    build_key_table(key, CAST_TABLE(table_ptr));
}

// Function 2: Encrypt
PLAYFAIR_C_API void EncryptPlayfair_C(const char* table_ptr, const char* plaintext, char* ciphertext) {
    // Need to cast the const char* to a non-const table[5][5] for the encrypt function
    // as the original C function expects a non-const table due to design, but 
    // the logic itself only reads from it. The cast is necessary for signature matching.
    encrypt_playfair(CAST_TABLE(table_ptr), plaintext, ciphertext);
}

// Function 3: Decrypt
PLAYFAIR_C_API void DecryptPlayfair_C(const char* table_ptr, const char* ciphertext, char* plaintext) {
    decrypt_playfair(CAST_TABLE(table_ptr), ciphertext, plaintext);
}