#include <cstdint>

#include "syscalls.hpp"

#define SEED 0x95DF09BA
#define ROL8(v) (v << 8 | v >> 24)
#define ROR8(v) (v >> 8 | v << 24)
#define ROX8(v) ((SEED % 2) ? ROL8(v) : ROR8(v))

static DWORD
HashSyscall(PCSTR FunctionName) {
    DWORD Hash = SEED;
    DWORD i = 0;

    while (FunctionName[i] != 0)
        Hash ^= *reinterpret_cast<WORD *>(reinterpret_cast<ULONG_PTR>(FunctionName) + i++) + ROR8(Hash);

    return Hash;
}

_Success_(return)

BOOL
GetSyscallList(_Out_ PSYSCALL_LIST pSyscallList) {
    DWORD Entries = 0;

    //
    // Get the PEB.
    //
    PPEB_LDR_DATA ldr = reinterpret_cast<PPEB>(__readgsqword(0x60))->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = nullptr;
    PVOID DllBase = nullptr;

    //
    // Get the base address of ntdll.dll. It's not guaranteed that ntdll.dll is the second module in the list, so we
    // will loop through the list until we find it.
    //
    for (auto LdrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(ldr->Reserved2[1]); LdrEntry->DllBase != NULL;
         LdrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(LdrEntry->Reserved1[0])) {
        DllBase = LdrEntry->DllBase;
        const auto DosHeader = static_cast<PIMAGE_DOS_HEADER>(DllBase);
        const auto NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        const auto DataDirectory = static_cast<PIMAGE_DATA_DIRECTORY>(NtHeaders->OptionalHeader.DataDirectory);
        const DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        //
        // If the virtual address of the export directory is zero, then the module doesn't export any functions.
        //
        if (!VirtualAddress)
            continue;

        ExportDirectory = RVA2VA(PIMAGE_EXPORT_DIRECTORY, DllBase, VirtualAddress);

        //
        // If this is the target DLL, then break out of the loop.
        //
        const auto szDllNme = RVA2VA(char *, DllBase, ExportDirectory->Name);

        if ((*reinterpret_cast<ULONG *>(szDllNme) | 0x20202020) != 0x6c64746e)
            continue;
        if ((*reinterpret_cast<ULONG *>(szDllNme + 4) | 0x20202020) == 0x6c642e6c)
            break;
    }

    //
    // If the export directory is null, then the module doesn't export any functions.
    //
    if (!ExportDirectory)
        return FALSE;

    std::uint32_t NumberOfNames = ExportDirectory->NumberOfNames;

    const auto pFunctionAddresses = RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    const auto szFunctionNames = RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    const auto pOrdinals = (RVA2VA(std::uint16_t *, DllBase, ExportDirectory->AddressOfNameOrdinals));

    const auto syscallTable = pSyscallList->Table;

    do {
        //
        // Is this a system call?
        //
        if (const auto szFunctionName = RVA2VA(char *, DllBase, szFunctionNames[NumberOfNames - 1]);
            *reinterpret_cast<std::uint16_t *>(szFunctionName) == 0x775a) {
            //
            // Save Hash of system call and the address.
            //
            syscallTable[Entries].Hash = HashSyscall(szFunctionName);
            syscallTable[Entries].Rva = pFunctionAddresses[pOrdinals[NumberOfNames - 1]];
            syscallTable[Entries].SyscallAddress = RVA2VA(PVOID, DllBase, syscallTable[Entries].Rva);
            syscallTable[Entries].Name = szFunctionName;

            if (++Entries == MAX_SYSCALLS)
                break;
        }
    } while (--NumberOfNames);

    //
    // Save the number of system calls.
    //
    pSyscallList->Entries = Entries;

    //
    // Sort the list by address in ascending order.
    //
    for (std::uint32_t i = 0; i < Entries - 1; i++) {
        for (std::uint32_t j = 0; j < Entries - i - 1; j++) {
            if (syscallTable[j].Rva > syscallTable[j + 1].Rva) {
                SYSCALL_ENTRY entry;
                //
                // Swap entries.
                //
                entry.Hash = syscallTable[j].Hash;
                entry.Rva = syscallTable[j].Rva;
                entry.Name = syscallTable[j].Name;
                entry.SyscallAddress = syscallTable[j].SyscallAddress;

                syscallTable[j].Hash = syscallTable[j + 1].Hash;
                syscallTable[j].Rva = syscallTable[j + 1].Rva;
                syscallTable[j].Name = syscallTable[j + 1].Name;
                syscallTable[j].SyscallAddress = syscallTable[j + 1].SyscallAddress;

                syscallTable[j + 1].Hash = entry.Hash;
                syscallTable[j + 1].Rva = entry.Rva;
                syscallTable[j + 1].Name = entry.Name;
                syscallTable[j + 1].SyscallAddress = entry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

_Success_(return >= 0) extern "C" DWORD GetSyscallNumber(_In_ const PSYSCALL_LIST pSyscallList,
                                                         _In_ const std::int32_t lFunctionHash) {
    for (std::uint32_t i = 0; i < pSyscallList->Entries; i++) {
        if (pSyscallList->Table[i].Hash == lFunctionHash)
            return i;
    }

    return -1;
}

PVOID GetSyscallAddress(_In_ PSYSCALL_LIST pSyscallList, _In_ std::int32_t lFunctionHash) {
    for (std::uint32_t i = 0; i < pSyscallList->Entries; i++) {
        if (pSyscallList->Table[i].Hash == lFunctionHash)
            return pSyscallList->Table[i].SyscallAddress;
    }

    return nullptr;
}

_Success_(return >= 0) DWORD GetSyscallHash(_In_ const PSYSCALL_LIST pSyscallList, _In_ const char *szFunctionName) {
    for (std::uint32_t i = 0; i < pSyscallList->Entries; i++) {
        if (strcmp(pSyscallList->Table[i].Name, szFunctionName) == 0)
            return pSyscallList->Table[i].Hash;
    }

    return -1;
}
