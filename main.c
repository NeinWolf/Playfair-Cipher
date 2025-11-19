#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_TEXT_LEN 1024

/* ==================== UTILITY FUNCTIONS ==================== */

// Converts to uppercase, removes non-letters, replaces J with I
void normalize_text(const char *input, char *output) {
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

/* ==================== KEY TABLE GENERATION ==================== */

// Builds 5x5 key table from key string
void build_key_table(const char *key, char table[5][5]) {
    int used[26] = {0};
    char normalized_key[MAX_TEXT_LEN];
    int k = 0;

    // Normalizes key (only letters, uppercase, J->I)
    normalize_text(key, normalized_key);

    // Fills from key first
    for (int i = 0; normalized_key[i] != '\0'; i++) {
        char c = normalized_key[i];
        int idx = c - 'A';
        if (c == 'J') idx = 'I' - 'A';
        if (!used[idx]) {
            used[idx] = 1;
            normalized_key[k++] = c;
        }
    }

    // Adds remaining letters A-Z (skips J, or treats J as I)
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
void find_position(char table[5][5], char ch, int *row, int *col) {
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

/* ==================== PLAINTEXT PREPARATION ==================== */

// Prepares plaintext into digraphs: removes non-letters, splits into pairs,
void prepare_plaintext(const char *input, char *output) {
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
                second = 'X';
                i += 1;
            } else {
                i += 2;
            }
        } else {
            second = 'X';
            i += 1;
        }

        output[k++] = first;
        output[k++] = second;
    }
    output[k] = '\0';
}

/* ==================== ENCRYPTION / DECRYPTION ==================== */

void encrypt_playfair(char table[5][5], const char *plaintext, char *ciphertext) {
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
            // Same row: shift right
            ciphertext[k++] = table[r1][(c1 + 1) % 5];
            ciphertext[k++] = table[r2][(c2 + 1) % 5];
        } else if (c1 == c2) {
            // Same column: shift down
            ciphertext[k++] = table[(r1 + 1) % 5][c1];
            ciphertext[k++] = table[(r2 + 1) % 5][c2];
        } else {
            // Rectangle: swap columns
            ciphertext[k++] = table[r1][c2];
            ciphertext[k++] = table[r2][c1];
        }
    }
    ciphertext[k] = '\0';
}

void decrypt_playfair(char table[5][5], const char *ciphertext, char *plaintext) {
    int len = strlen(ciphertext);
    int k = 0;

    for (int i = 0; i < len; i += 2) {
        char a = toupper((unsigned char)ciphertext[i]);
        char b = toupper((unsigned char)ciphertext[i + 1]);

        if (a == 'J') a = 'I';
        if (b == 'J') b = 'I';

        int r1, c1, r2, c2;
        find_position(table, a, &r1, &c1);
        find_position(table, b, &r2, &c2);

        if (r1 == r2) {
            // Same row: shift left
            ciphertext[i];
            plaintext[k++] = table[r1][(c1 + 4) % 5];
            plaintext[k++] = table[r2][(c2 + 4) % 5];
        } else if (c1 == c2) {
            // Same column: shift up
            plaintext[k++] = table[(r1 + 4) % 5][c1];
            plaintext[k++] = table[(r2 + 4) % 5][c2];
        } else {
            // Rectangle: swap columns
            plaintext[k++] = table[r1][c2];
            plaintext[k++] = table[r2][c1];
        }
    }
    plaintext[k] = '\0';
}

