#pragma once
#include <atomic>
#include <vector>

#include <Windows.h>
#include <Psapi.h>
#include <direct.h>

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#include <vector>
#include <Capstone/x86.h>
#include <Capstone/capstone.h>

#include "nt.hpp"

extern volatile std::atomic_bool g_bTerminateCurrentTask;

struct DumpTarget {
    void *rpBaseAddress;
    std::byte *lpLocalBuffer;
    std::size_t dwLocalBufferSize;
    const wchar_t *wszModuleName;
};

//
// Represents a dumper object.
//
typedef struct _DUMPER {
    const wchar_t *ProcessName; // Name of the target process.
    csh capstoneHandle;
    std::vector<DumpTarget> DumpTargets;
    std::vector<MODULEINFO> ModuleInformations;
    DWORD ProcessId; // ID of the target process.
    HANDLE hProcess; // Handle to the target process.
    const wchar_t *OutputPath; // Path to the output directory.
    FLOAT DecryptionFactor; // Decrypt no access memory regions.
    BOOL UseTimestamp; // Flag to indicate whether to use timestamp in output filename.
} DUMPER, *PDUMPER;

//
// Creates a new dumper object. Initializes the object with the specified process name, output path, and decryption
// flag.
_Success_(return) bool DumperCreate(
    _Out_ PDUMPER pDumper,
    _In_ const wchar_t *szProcessName,
    _In_ const wchar_t *wszTargetModule,
    _In_ const wchar_t *szOutputPath,
    _In_ FLOAT fDecryptionFactor,
    _In_ bool bUseTimestamp);

//
// Dumps the target process memory to disk. Decrypts no access memory regions if the decryption flag is set.
//
bool DumperDumpToDisk(_In_ PDUMPER Dumper);

//
// Destroys the specified dumper object. Closes the handle to the target process.
//
_Success_(return == EXIT_SUCCESS)

INT
DumperDestroy(_In_ PDUMPER Dumper);


bool GetModuleInfosIntoVector(_In_ HANDLE hProcess, _Out_ std::vector<MODULEINFO> &moduleInformations);

bool GetRemoteProcessModuleNames(_In_ HANDLE hProcess, _Out_ std::vector<const wchar_t *> &moduleNames);
