#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <TlHelp32.h>
#include "spcoe_exit.hpp"

#if defined(_OUT_PUT_LOG)
#define logger(format, ...) printf(format, __VA_ARGS__)
#else
#define logger(format, ...)
#endif


int main(int argc, const char * argv[]) {
    if(argc != 3){
        logger("Parameter error\n");
        logger("Tips: [process] [module]\n");
        return 0;
    }

    const char* process_name = argv[1];
    const char* module_name = argv[2];

    unsigned pid = 0;
    HANDLE hprocess = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 process_entry = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot_handle == INVALID_HANDLE_VALUE || snapshot_handle == nullptr) {
        logger("CreateToolhelp32Snapshot failed\n");
        return 0;
    }
    auto close_1 = std::experimental::scope_exit([snapshot_handle] { CloseHandle(snapshot_handle); });

    bool success = Process32First(snapshot_handle, &process_entry);
    while (success) {
        if (_stricmp(process_entry.szExeFile, process_name) == 0) {
            hprocess = OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID);
            if (hprocess == INVALID_HANDLE_VALUE || hprocess == nullptr) {
                logger("OpenProcess failed\n");
                return 0;
            }
            pid = process_entry.th32ProcessID;
            break;
        }
        success = Process32Next(snapshot_handle, &process_entry);
    }
    auto close_2 = std::experimental::scope_exit([hprocess] { CloseHandle(hprocess); });

    HANDLE handle = nullptr;
    HMODULE hmodule = nullptr;
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);  //所有进程的句柄
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        logger("CreateToolhelp32Snapshot failed\n");
        return 0;
    }
    auto close_3 = std::experimental::scope_exit([handle] { CloseHandle(handle); });

    MODULEENTRY32 module_entry{ .dwSize = sizeof(MODULEENTRY32) };
    success = Module32First(handle, &module_entry);
    if (success) {
        do {
            if (_stricmp(module_entry.szModule, module_name) == 0) {
                hmodule = module_entry.hModule;
                break;
            }
        } while (Module32Next(handle, &module_entry));
    }

    if(hmodule == nullptr){
        logger("module %s not found\n", module_name);
        return 0;
    }
    unsigned __int8* imagebuffer = new unsigned __int8[module_entry.modBaseSize];
    memset(imagebuffer, 0, module_entry.modBaseSize);
    auto close_4 = std::experimental::scope_exit([imagebuffer] { delete[] imagebuffer; });
    ReadProcessMemory(hprocess, hmodule, imagebuffer, module_entry.modBaseSize, nullptr);

    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(imagebuffer);
    if(dos_header->e_magic != IMAGE_DOS_SIGNATURE){
        return 0;
    }

    IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(dos_header->e_lfanew + imagebuffer);
    if(nt_headers->Signature != IMAGE_NT_SIGNATURE){
        return 0;
    }

    auto section_headers = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section_headers){
        section_headers->PointerToRawData = section_headers->VirtualAddress;
        section_headers->SizeOfRawData = section_headers->Misc.VirtualSize;
    }

    std::string filepath = std::filesystem::current_path()
            .string()
            .append("\\")
            .append("dump_")
            .append(module_name);

    std::ofstream os(filepath, std::ios::binary);
    if(os.is_open()){
        os.write(reinterpret_cast<char*>(imagebuffer), module_entry.modBaseSize);
        os.flush();
        os.close();
    }

    printf("Dumped to %s\n", filepath.c_str());
    return 0;
}
