#include "chiffrement.h"
#include <iostream>
#include <iomanip>

// D�chiffre le shellcode t�l�charg�
void decrypt_shellcode(char* shellcode, char* decrypted_shellcode, size_t size) {

    // R�cup�rer la cl� � partir des trois premiers caract�res du shellcode
    unsigned char key[3];
    key[0] = (unsigned char)shellcode[0];
    key[1] = (unsigned char)shellcode[1];
    key[2] = (unsigned char)shellcode[2];

    for (size_t i = 0; i < size; ++i) {
        decrypted_shellcode[i] = shellcode[i + 3] ^ key[i % 3];
    }

    std::cout << "Shellcode t�l�charg� (en hexad�cimal) :\n";
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", (unsigned char)decrypted_shellcode[i]);
        if ((i + 1) % 16 == 0) { // Affiche 16 octets par ligne
            printf("\n");
        }
    }
    printf("\n");
}