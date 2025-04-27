#ifdef DEBUG
#include <iostream>
#endif

#define LOADER
#include "common.h"


void load_library(BYTE *image_base) {
    const var nt_headers = get_nt_headers(image_base);

    const var import_tb_addr =
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    const var import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(image_base + import_tb_addr);

    // Characteristic: 0 for terminating null import descriptor
    for (var i = 0; import_descriptor[i].Characteristics != 0 && import_descriptor[i].FirstThunk != 0; i++) {
        const var module_name = reinterpret_cast<LPCSTR>(image_base + import_descriptor[i].Name);

        var lib = GetModuleHandle(module_name);
        if (lib == INVALID_HANDLE_VALUE || lib == nullptr) {
            lib = LoadLibrary(module_name);
            if (lib == INVALID_HANDLE_VALUE || lib == nullptr) {
#ifdef DEBUG
                std::cerr << "Failed to load " << module_name << std::endl;
#endif
                exit(1);
            }

        }

        // OriginalFirstThunk -> IDT (import name table), FirstThunk -> IAT (import address table)
        // bef load, IDT -> IMAGE_IMPORT_BY_NAME, IAT -> IMAGE_IMPORT_BY_NAME
        // aft load, IDT -> IMAGE_IMPORT_BY_NAME, IAT is the address of the function
        // we need to simulate this process
        const var idt = reinterpret_cast<IMAGE_THUNK_DATA *>(image_base + import_descriptor[i].OriginalFirstThunk);
        const var iat = reinterpret_cast<IMAGE_THUNK_DATA *>(image_base + import_descriptor[i].FirstThunk);

        for (var j = 0l; idt[j].u1.AddressOfData != 0; j++) {
            FARPROC function_addr;

            if (const var data_addr = idt[j].u1.AddressOfData; data_addr & IMAGE_ORDINAL_FLAG) {
                // import via ORDINAL Number
                function_addr = GetProcAddress(lib, MAKEINTRESOURCE(IMAGE_ORDINAL(data_addr)));
                if (function_addr == nullptr) {
#ifdef DEBUG
                    std::cerr << "Failed to get function ORDINAL "
                            << (data_addr & 0xFFFF) << " address of lib " << module_name << std::endl;
#endif
                    exit(1);
                }
            } else {
                // import via function name
                const var hint_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(image_base + data_addr);
                const var func_name = reinterpret_cast<char *>(&hint_name->Name);
                function_addr = GetProcAddress(lib, func_name);

                if (function_addr == nullptr) {
#ifdef DEBUG
                    std::cerr << GetLastError() << std::endl;
                    std::cerr << "Failed to get function "
                            << func_name << " address of lib " << module_name << std::endl;
#endif
                    exit(1);
                }
            }

            iat[j].u1.Function = reinterpret_cast<ULONG_PTR>(function_addr);
        }
    }
}

void update_reloc(BYTE *image_base) {
    const var nt_headers = get_nt_headers(image_base);
    const var reloc_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const var reloc_tb_addr = reloc_directory->VirtualAddress + image_base;

    const var image_base_delta = reinterpret_cast<ULONGLONG>(image_base) - nt_headers->OptionalHeader.ImageBase;

    if (image_base_delta == 0 || reloc_directory->VirtualAddress == 0) {
        return;
    }

    var reloc_tb_header = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reloc_tb_addr);
    while (reloc_tb_header->VirtualAddress != 0) {
        // (total size - header size) / (item size)
        const var item_count = (reloc_tb_header->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (var i = 0; i < item_count; i++) {
            const var reloc_item = *(reinterpret_cast<WORD *>(reloc_tb_header + 1) + i);
            // type: 4 bits, offset: 12 bits
            const var type = reloc_item >> 12;
            const var offset = reloc_item & 0x0FFF;

            const var reloc_addr = reinterpret_cast<DWORD *>(image_base + reloc_tb_header->VirtualAddress + offset);

            switch (type) {
                case IMAGE_REL_BASED_HIGH:
                    // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the high value of a 32-bit word.
                    *reinterpret_cast<PWORD>(reloc_addr) += HIWORD(image_base_delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the low half of a 32-bit word.
                    *reinterpret_cast<PWORD>(reloc_addr) += LOWORD(image_base_delta);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
                    *static_cast<PDWORD>(reloc_addr) += static_cast<DWORD>(image_base_delta);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    // The base relocation applies the difference to the 64-bit field at offset.
                    *reinterpret_cast<PDWORD64>(reloc_addr) += image_base_delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE: // The base relocation is skipped. This type can be used to pad a block.
                default:
                    break;
            }
        }
        reloc_tb_header = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
            reinterpret_cast<char *>(reloc_tb_header) + reloc_tb_header->SizeOfBlock);
    }
}

BYTE *load_pe(BYTE *buffer) {
    const var nt_headers = get_nt_headers(buffer);

    // LINUX: mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const var image_base = static_cast<BYTE *>(
        VirtualAlloc(nullptr,
                     nt_headers->OptionalHeader.SizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
    );

    if (image_base == nullptr) {
#ifdef DEBUG
        std::cerr << "Failed to allocate memory" << std::endl;
#endif
        exit(1);
    }

    // cpy header
    memcpy(image_base, buffer, nt_headers->OptionalHeader.SizeOfHeaders);
    // cpy sections

    const var sections = IMAGE_FIRST_SECTION(nt_headers);
    for (var i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const var dst = image_base + sections[i].VirtualAddress;
        const var src = buffer + sections[i].PointerToRawData;

        if (const var size = sections[i].SizeOfRawData; size == 0) {
            memset(dst, 0, sections[i].Misc.VirtualSize);
        } else {
            memcpy(dst, src, size);
        }
    }

    // set mem permissions
    VirtualProtect(image_base, nt_headers->OptionalHeader.SizeOfImage, PAGE_READONLY, nullptr);
    for (var i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const var dst = image_base + sections[i].VirtualAddress;
        const var perm = sections[i].Characteristics;
        const var flag = perm & IMAGE_SCN_MEM_EXECUTE
                             ? perm & IMAGE_SCN_MEM_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ
                             : perm & IMAGE_SCN_MEM_WRITE ? PAGE_READWRITE : PAGE_READONLY;

        VirtualProtect(dst, sections[i].Misc.VirtualSize, flag, nullptr);
    }

    load_library(image_base);
    update_reloc(image_base);
    return image_base;
}


void run(BYTE *image_base) {
    const var nt_headers = get_nt_headers(image_base);

    const var enter_addr = image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
    (reinterpret_cast<void(*)()>(enter_addr))();
}

int main() {
    const var self = GetModuleHandle(nullptr);
    var nt_header = get_nt_headers(reinterpret_cast<BYTE *>(self));

    // ±éÀú½ÚÇø
    var section = IMAGE_FIRST_SECTION(nt_header);
    const var num_sections = nt_header->FileHeader.NumberOfSections;

    for (DWORD i = 0; i < num_sections; i++, section++) {
        if (const var target_section = PACKED_SEC_NAME;
            memcmp(section->Name, target_section, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            const var address = reinterpret_cast<BYTE *>(self) + section->VirtualAddress;
            const var size = section->Misc.VirtualSize;

            decode(address, size);
            const auto loader_pe = load_pe(address);
            run(loader_pe);
            break;
        }
    }
}
