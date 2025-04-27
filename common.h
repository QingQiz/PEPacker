#ifndef COMMON_H
#define COMMON_H
#include <windows.h>
#include <winnt.h>


#define var auto

inline IMAGE_NT_HEADERS *get_nt_headers(BYTE *buffer) {
    const var dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(buffer);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
#ifdef DEBUG
        std::cerr << "Invalid PE file: " << buffer << std::endl;
#endif
        exit(0);
    }
    const var nt_header = reinterpret_cast<IMAGE_NT_HEADERS *>(buffer + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
#ifdef DEBUG
        std::cerr << "Invalid PE file: " << buffer << std::endl;
#endif
        exit(1);
    }
    return nt_header;
}

#define PACKED_SEC_NAME ".packed"

#ifdef LOADER

// functions for loader
inline void decode(BYTE *buffer, const DWORD size) {
    for (auto i = 0; i < size; i++) {
        buffer[i] ^= 0x55;
    }
}

#elifdef PACKER

// functions for packer
// simple encoder
// can be replaced with more complex encoder, such as RC4, AES, etc.
inline void encode(BYTE *buffer, DWORD size) {
    for (auto i = 0; i < size; i++) {
        buffer[i] ^= 0x55;
    }
}


#endif
#endif //COMMON_H
