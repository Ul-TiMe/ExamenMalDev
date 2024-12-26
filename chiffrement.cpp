#include "chiffrement.h"
#include <iostream>
#include <iomanip>

// Déchiffre le shellcode téléchargé
void decrypt_shellcode(char* shellcode, size_t size) {

    // Récupérer la clé à partir des trois premiers caractères du shellcode
    unsigned char key[3];
    key[0] = (unsigned char)shellcode[0];
    key[1] = (unsigned char)shellcode[1];
    key[2] = (unsigned char)shellcode[2];

    // Le reste du shellcode est crypté
    char* encryptedPayload = shellcode + 3; // Le reste du shellcode chiffré
    size_t decryptedSize = size - 3; // Taille du shellcode déchiffré

    // Déchiffrement XOR sur le reste du shellcode
    for (size_t i = 0; i < decryptedSize; ++i) {
        encryptedPayload[i] ^= key[i % 3]; // Déchiffrement XOR directement sur le tableau
    }

    //// Afficher le shellcode déchiffré en hexadécimal
    //std::cout << "Shellcode déchiffré :\n";
    //for (size_t i = 0; i < decryptedSize; ++i) {
    //    std::cout << "\\x" << std::setw(2) << std::setfill('0') << std::hex << (int)(unsigned char)encryptedPayload[i];
    //}
    //std::cout << std::endl;

    std::cout << "Shellcode téléchargé (en hexadécimal) :\n";
    for (size_t i = 0; i < decryptedSize; ++i) {
        printf("%02X ", (unsigned char)encryptedPayload[i]);
        if ((i + 1) % 16 == 0) { // Affiche 16 octets par ligne
            printf("\n");
        }
    }
    printf("\n");
}