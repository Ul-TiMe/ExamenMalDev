#ifndef CHIFFREMENT_H
#define CHIFFREMENT_H

#include <cstddef>
#include <string>
#include <Windows.h>


// D�chiffre le shellcode � l'aide d'un XOR
void decrypt_shellcode(char* shellcode, size_t size);

#endif // CHIFFREMENT_H
