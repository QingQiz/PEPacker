#include <algorithm>
#include <fstream>
#include <ranges>
#include <span>
#include <vector>
#include <bits/ranges_algo.h>
#include <iostream>

#define PACKER
#include "common.h"

extern "C" const char _binary_loader_bin_start[];
extern "C" const char _binary_loader_bin_end[];

void assert_enough_space_bef_fst_section(
    const BYTE *loader_pe, IMAGE_SECTION_HEADER *section_headers, const DWORD num_sections
) {
    var selected_sections = std::span(section_headers, num_sections) | std::views::filter([](var x) {
        return x.PointerToRawData != 0;
    });
    const var min_raw_data = std::ranges::min_element(
        selected_sections, {}, &IMAGE_SECTION_HEADER::PointerToRawData)->PointerToRawData;

    if (loader_pe + min_raw_data - reinterpret_cast<BYTE *>(section_headers + num_sections) < sizeof(
            IMAGE_SECTION_HEADER)) {
        std::cerr << "No enough space for new section" << std::endl;
        exit(1);
    }
}

void assert_same_arch(const IMAGE_NT_HEADERS *loader_nt_header, const WORD target_arch) {
    if (loader_nt_header->OptionalHeader.Magic != target_arch) {
#ifdef _WIN64
        std::cerr << "Loader is x64, target is x86" << std::endl;
#else
        std::cerr << "Loader is x86, target is x64" << std::endl;
#endif
        exit(1);
    }
}

template<typename T>
T align_data(const T data, const T align) {
    return (data + align - 1) / align * align;
}

void pad_with_zero(std::ofstream &of, const DWORD size) {
    if (size == 0) return;

    const std::vector<char> data(size, 0);
    of.write(data.data(), size);
}

void create_new_section(
    IMAGE_SECTION_HEADER *const new_section_header,
    IMAGE_NT_HEADERS *const nt_header,
    const IMAGE_SECTION_HEADER *section_headers,
    const DWORD target_size,
    const long long loader_pe_size,
    const WORD num_sections
) {
    memset(new_section_header, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(new_section_header->Name, PACKED_SEC_NAME, sizeof(PACKED_SEC_NAME));
    new_section_header->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    const var max_section_va = std::ranges::max(
        std::span(section_headers, num_sections) |
        std::views::transform([](var x) { return x.VirtualAddress + x.Misc.VirtualSize; })
    );

    const var file_alignment = nt_header->OptionalHeader.FileAlignment;
    const var section_alignment = nt_header->OptionalHeader.SectionAlignment;

    // align data in file
    const var target_data_pa_aligned = align_data(static_cast<DWORD>(loader_pe_size), file_alignment);
    new_section_header->PointerToRawData = target_data_pa_aligned;
    const var target_data_size_aligned = align_data(target_size, file_alignment);
    new_section_header->SizeOfRawData = target_data_size_aligned;

    // align data in memory
    const var target_data_va_aligned = align_data(max_section_va, section_alignment);
    new_section_header->VirtualAddress = target_data_va_aligned;
    new_section_header->Misc.VirtualSize = target_size;

    // update nt header
    nt_header->OptionalHeader.SizeOfImage = new_section_header->VirtualAddress +
                                            align_data(target_size, section_alignment);
    nt_header->FileHeader.NumberOfSections++;
}

void write_to_file(
    const std::string &output_fn,
    const BYTE *const loader_pe, const long long loader_pe_size,
    const BYTE *const target_data, const DWORD target_size,
    const _IMAGE_SECTION_HEADER *const new_section_header
) {
    var of = std::ofstream(output_fn, std::ios::binary);
    if (!of.is_open()) {
        std::cerr << "Failed to open file: " << output_fn << std::endl;
        exit(1);
    }

    // write to new pe file
    of.write(reinterpret_cast<const char *>(loader_pe), loader_pe_size);
    pad_with_zero(of, new_section_header->PointerToRawData - loader_pe_size);
    of.write(reinterpret_cast<const std::ostream::char_type *>(target_data), target_size);
    pad_with_zero(of, new_section_header->SizeOfRawData - target_size);
    of.close();
}

int main(const int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file>" << std::endl;
        exit(1);
    }

    const var target = argv[1];

    var inf = std::ifstream(target, std::ios::binary | std::ios::ate);
    if (!inf.is_open()) {
        std::cerr << "Failed to open file: " << target << std::endl;
        exit(1);
    }
    const var target_size = static_cast<DWORD>(inf.tellg());
    const var target_data = new BYTE[target_size];
    inf.seekg(0, std::ios::beg);
    inf.read(reinterpret_cast<char *>(target_data), target_size);
    inf.close();

    // target: PE file to be packed
    const var target_nt_header = get_nt_headers(target_data);
    const var target_arch_magic = target_nt_header->OptionalHeader.Magic;
    encode(target_data, target_size);

    const var loader_pe_size = _binary_loader_bin_end - _binary_loader_bin_start;
    const var loader_pe = new BYTE[loader_pe_size];
    std::copy(_binary_loader_bin_start, _binary_loader_bin_end, loader_pe);

    const var loader_nt_header = get_nt_headers(loader_pe);
    assert_same_arch(loader_nt_header, target_arch_magic);

    // insert target_data to a new section of loader
    const var nt_header = get_nt_headers(loader_pe);
    const var section_headers = IMAGE_FIRST_SECTION(nt_header);
    const var num_sections = nt_header->FileHeader.NumberOfSections;
    assert_enough_space_bef_fst_section(loader_pe, section_headers, num_sections);

    const var new_section_header = &section_headers[num_sections];
    create_new_section(new_section_header, nt_header, section_headers, target_size, loader_pe_size, num_sections);

    // write output
    const var packed_target = std::string(target) + ".packed.exe";
    write_to_file(packed_target, loader_pe, loader_pe_size, target_data, target_size, new_section_header);

    delete[] loader_pe;
    return 0;
}
