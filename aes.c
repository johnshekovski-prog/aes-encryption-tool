#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

// Функция за обработка на грешки
void handleErrors() {
    printf("Error in OpenSSL.\n");
    exit(1);
}

// ================= ENCRYPT FUNCTION =================
int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx;  // контекст за криптиране
    int len;
    int ciphertext_len;

    // Създаване на нов контекст
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Инициализация на AES-128-CBC криптиране
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    // Криптиране на данните (основна част)
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // Финализиране (padding)
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    // Освобождаване на паметта
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// ================= DECRYPT FUNCTION =================
int decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;  // контекст за декриптиране
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Инициализация за декриптиране
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    // Декриптиране
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Финализиране (махане на padding)
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// ================= MAIN =================
int main() {

    // 16 байта ключ → AES-128
    unsigned char key[16] = "0123456789012345";

    // IV (Initialization Vector) - също 16 байта
    unsigned char iv[16]  = "abcdef9876543210";

    // Оригинален текст
    unsigned char plaintext[] = "CyberSecurity Lab";

    // Буфери за резултати
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    printf("Original Text: %s\n", plaintext);

    // ===== ENCRYPT =====
    int cipher_len = encrypt(
        plaintext,
        strlen((char *)plaintext),
        key,
        iv,
        ciphertext
    );

    // Печат на криптирания текст (hex формат)
    printf("Ciphertext (%d bytes):\n", cipher_len);
    for(int i = 0; i < cipher_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // ===== DECRYPT =====
    int decrypted_len = decrypt(
        ciphertext,
        cipher_len,
        key,
        iv,
        decryptedtext
    );

    // Добавяме null terminator за да е валиден string
    decryptedtext[decrypted_len] = '\0';

    printf("Decrypted Text: %s\n", decryptedtext);

    return 0;
}
