cmake_minimum_required(VERSION 3.30)
project(PEPacker)

set(CMAKE_CXX_STANDARD 20)

add_executable(loader loader.cpp
        common.h)
set_target_properties(loader PROPERTIES OUTPUT_NAME "loader")
set_target_properties(loader PROPERTIES SUFFIX ".bin")
# make loader as small as possible
target_compile_options(loader PRIVATE
        -Os
        -fno-stack-protector -fomit-frame-pointer
        -Wl,--build-id=none
        -fno-asynchronous-unwind-tables -fno-unwind-tables)


add_custom_command(
        OUTPUT loader.bin.o
        COMMAND ${CMAKE_OBJCOPY}
            -I binary -O elf64-x86-64
            --rename-section
            .data=.loader,alloc,load,readonly,data,contents loader.bin loader.bin.o
        DEPENDS loader.bin
)

add_executable(packer packer.cpp loader.bin.o)
