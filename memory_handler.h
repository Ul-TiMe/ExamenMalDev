#ifndef MEMORY_HANDLER_H
#define MEMORY_HANDLER_H

#include <cstddef>

// Injecte et ex�cute un shellcode
bool inject_shellcode(char* shellcode, size_t size);

#endif // MEMORY_HANDLER_H
