#include <cstdint>
#include <ctime>
#include <atomic>

#include "dumper.hpp"

#include <filesystem>
#include <future>

#include "sections.hpp"
#include "out.hpp"
#include "syscalls.hpp"

volatile std::atomic_bool g_bTerminateCurrentTask = false;

_Success_(return > 0)

static DWORD
GetProcessIdByName(_In_ LPCWSTR wszProcessName);

static bool GetModuleInfo(_In_ HANDLE hProcess, _In_ const wchar_t *wszModuleName, _Out_ MODULEINFO *ModuleInfo);

bool WriteImagesToDisk(_In_ PDUMPER pDumper);

bool WriteImageToDisk(_In_ PDUMPER Dumper, _In_ PBYTE Buffer, _In_ SIZE_T Size, _In_ const wchar_t *wszModuleName);

bool BuildInitialImage(_In_ PDUMPER pDumper, const MODULEINFO &target, _Out_ PBYTE *pBuffer);

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);

// =====================================================================================================================
// Public functions
// =====================================================================================================================

_Success_(return) bool DumperCreate(
    _Out_ const PDUMPER pDumper,
    _In_ const wchar_t *szProcessName,
    _In_ const wchar_t *wszTargetModule,
    _In_ const wchar_t *szOutputPath,
    _In_ const FLOAT fDecryptionFactor,
    _In_ const bool bUseTimestamp) {
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    if (const auto status = cs_open(cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_64, &pDumper->capstoneHandle);
        status != cs_err::CS_ERR_OK) {
        error("Failed to initialize capstone for decrypted page clean-up.");
        return false;
    }

    cs_option(pDumper->capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(pDumper->capstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
    pDumper->ProcessName = szProcessName;

    if (lstrcmpW(wszTargetModule, L"all") != 0)
        pDumper->DumpTargets.push_back(DumpTarget{nullptr, nullptr, 0, wszTargetModule});

    pDumper->OutputPath = szOutputPath;
    pDumper->DecryptionFactor = fDecryptionFactor;
    pDumper->ProcessId = 0;
    pDumper->UseTimestamp = bUseTimestamp;

    //
    // Initialize the syscall list.
    //
    if (!NtInitialize()) {
        error("Failed to initialize the syscall list");
        return false;
    }

    //
    // Get the process ID of the target process.
    //
    pDumper->ProcessId = GetProcessIdByName(szProcessName);

    if (!pDumper->ProcessId)
        warn("Waiting for target process to open...");

    while (!pDumper->ProcessId) {
        _mm_pause();
        pDumper->ProcessId = GetProcessIdByName(szProcessName);
    }

    InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);

    ClientId.UniqueProcess = reinterpret_cast<HANDLE>(pDumper->ProcessId);
    ClientId.UniqueThread = nullptr;

    //
    // Open a handle to the target process.
    //

    if (const NTSTATUS ntOpenProcessStatus = NtOpenProcess(&pDumper->hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes,
                                                           &ClientId)
        ; static_cast<NTSTATUS>(ntOpenProcessStatus) < 0) {
        error("Failed to open a handle to the target process (0x%08X)", ntOpenProcessStatus);
        return false;
    }

    //
    // Get the module information of the target process.
    //
    {
        std::vector<const wchar_t *> names;
        std::vector<MODULEINFO> moduleinfos{};
        std::uint32_t attemptCount = 0;
        while (true) {
            if (const auto success = GetModuleInfosIntoVector(pDumper->hProcess, moduleinfos); success) break;

            if (attemptCount < 69) {
                warn("Attempting to get module info for remote target process [%d/%d]", attemptCount + 1, 70);
                attemptCount++;
            } else {
                error("Failed to get the module information of the target process");
                return false;
            }
            _mm_pause();
        }

        pDumper->ModuleInformations = std::move(moduleinfos);

        if (lstrcmpW(wszTargetModule, L"all") == 0) {
            GetRemoteProcessModuleNames(pDumper->hProcess, names);

            for (const auto &name: names) {
                MODULEINFO moduleInfo{};
                GetModuleInfo(pDumper->hProcess, name, &moduleInfo);

                pDumper->DumpTargets.push_back(DumpTarget{moduleInfo.lpBaseOfDll, nullptr, 0, name});
            }
        }
    }

    //
    // Set the handler for the CTRL+C event.
    //
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        error("Failed to set the console control handler");
        return false;
    }

    return true;
}

bool
DumperDumpToDisk(_In_ PDUMPER const pDumper) {
    bool success = false;

    std::vector<std::future<std::pair<std::uintptr_t, unsigned char *> > > futures;
    for (auto &pendingTarget: pDumper->DumpTargets) {
        auto targetModuleInfo = MODULEINFO{};


        if (!GetModuleInfo(pDumper->hProcess, pendingTarget.wszModuleName, &targetModuleInfo)) {
            warn("Cannot dump %ls, cannot fetch module information.", pendingTarget.wszModuleName);
            continue;
        }
        futures.push_back(
            std::async(std::launch::async,
                       [&pDumper, &pendingTarget, targetModuleInfo]() -> std::pair<std::uintptr_t, unsigned char *> {
                           unsigned char *pBuffer{};

                           // Read the entire image of the target process.
                           if (!BuildInitialImage(pDumper, targetModuleInfo, &pBuffer)) {
                               return std::pair{0ull, nullptr};
                           }

                           // Resolve the sections of the image.
                           if (!ResolveSections(pDumper, targetModuleInfo, &pBuffer)) {
                               return std::pair{0ull, nullptr};
                           }

                           pendingTarget.lpLocalBuffer = reinterpret_cast<std::byte *>(pBuffer);
                           pendingTarget.rpBaseAddress = targetModuleInfo.lpBaseOfDll;
                           pendingTarget.dwLocalBufferSize = targetModuleInfo.SizeOfImage;

                           return std::pair{targetModuleInfo.SizeOfImage, pBuffer};
                       }));
    }

    while (!futures.empty()) {
        for (auto start = futures.begin(); start != futures.end() && !futures.empty();) {
            if (start->wait_for(std::chrono::milliseconds{2000}) == std::future_status::timeout) {
                ++start;
                continue;
            }

            const auto [bufferSize, bufferPointer] = start->get();
            info("obtained %llu bytes on memory buffer %p", bufferSize, bufferPointer);

            for (const auto &[rpBaseAddress, lpLocalBuffer, dwLocalBufferSize, wszModuleName]: pDumper->DumpTargets) {
                if (lpLocalBuffer == static_cast<const void *>(bufferPointer) && dwLocalBufferSize ==
                    bufferSize) {
                    info("writing image %ls (%llu bytes) to disk...", wszModuleName, dwLocalBufferSize);
                    if (!WriteImageToDisk(pDumper, reinterpret_cast<unsigned char *>(lpLocalBuffer),
                                          dwLocalBufferSize, wszModuleName))
                        warn("failed to write image %ls to disk", wszModuleName);
                }
            }

            start = futures.erase(start);
        }
    }

    return true;
}

_Success_(return == EXIT_SUCCESS)

INT
DumperDestroy(_In_ PDUMPER Dumper) {
    NTSTATUS Status;

    //
    // Close the handle to the target process.
    //
    Status = NtClose(Dumper->hProcess);

    return !NT_SUCCESS(Status);
}

// =====================================================================================================================
// Private functions
// =====================================================================================================================

_Success_(return > 0) DWORD GetProcessIdByName(_In_ const wchar_t *wszProcessName) {
    NTSTATUS ntStatus{};

    PVOID pBuffer = nullptr;
    DWORD dwProcessId = 0;

    //
    // Reallocate the buffer until it's large enough to store the process information.
    //

    std::size_t bufferSize = NtBufferSize;
    do {
        const auto lpTemporal = realloc(pBuffer, bufferSize);

        if (lpTemporal == nullptr) {
            free(pBuffer);
            return 0;
        }

        pBuffer = lpTemporal;
    } while ((ntStatus = NtQuerySystemInformation(::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, pBuffer,
                                                  bufferSize,
                                                  reinterpret_cast<PULONG>(&bufferSize))) ==
             STATUS_INFO_LENGTH_MISMATCH); // Reallocate until we have the required size.

    //
    // Check if the system call was successful.
    //
    if (NT_SUCCESS(ntStatus)) {
        //
        // Iterate over the process list.
        //
        for (auto ProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(pBuffer);
             ProcessInfo->NextEntryOffset != 0;
             ProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                 reinterpret_cast<PUCHAR>(ProcessInfo) + ProcessInfo->NextEntryOffset)) {
            //
            // Check if the process name matches the target process name.
            //
            if (ProcessInfo->ImageName.Buffer && !_wcsicmp(ProcessInfo->ImageName.Buffer, wszProcessName)) {
                dwProcessId = reinterpret_cast<DWORD>(ProcessInfo->UniqueProcessId);
                break;
            }
        }
    }

    free(pBuffer);
    return dwProcessId;
}


bool GetRemoteProcessModuleNames(_In_ const HANDLE hProcess, _Out_ std::vector<const wchar_t *> &moduleNames) {
    HMODULE Modules[1024];
    std::uint32_t requireModuleBytes;

    if (!K32EnumProcessModules(hProcess, Modules, sizeof(Modules), reinterpret_cast<LPDWORD>(&requireModuleBytes)))
        return false;

    const std::uint32_t enumeratedCount = requireModuleBytes / static_cast<std::uint32_t>(sizeof(HMODULE));

    for (std::uint32_t i = 0; i < enumeratedCount; i++) {
        const auto moduleName = new wchar_t [MAX_PATH];

        if (!K32GetModuleFileNameExW(hProcess, Modules[i], moduleName, MAX_PATH)) {
            delete [] moduleName;
            continue;
        }

        moduleNames.push_back(wcsrchr(moduleName, L'\\') + 1);
    }

    return true;
}

bool GetModuleInfosIntoVector(_In_ const HANDLE hProcess, _Out_ std::vector<MODULEINFO> &moduleInformations) {
    HMODULE Modules[1024];
    std::uint32_t requireModuleBytes;

    if (!K32EnumProcessModules(hProcess, Modules, sizeof(Modules), reinterpret_cast<LPDWORD>(&requireModuleBytes)))
        return false;

    const std::uint32_t enumeratedCount = requireModuleBytes / static_cast<std::uint32_t>(sizeof(HMODULE));

    for (std::uint32_t i = 0; i < enumeratedCount; i++) {
        WCHAR Name[MAX_PATH];

        if (!K32GetModuleFileNameExW(hProcess, Modules[i], Name, MAX_PATH)) {
            continue;
        }

        MODULEINFO moduleinfo{};

        if (K32GetModuleInformation(hProcess, Modules[i], &moduleinfo, sizeof(MODULEINFO)))
            moduleInformations.emplace_back(moduleinfo);
        else
            warn("Failed to get module information for module %ls", Name);
    }

    return true;
}

bool GetModuleInfo(_In_ const HANDLE hProcess, _In_ const wchar_t *wszModuleName, _Out_ MODULEINFO *ModuleInfo) {
    HMODULE Modules[1024];
    std::uint32_t requireModuleBytes;

    if (!K32EnumProcessModules(hProcess, Modules, sizeof(Modules), reinterpret_cast<LPDWORD>(&requireModuleBytes)))
        return false;

    const std::uint32_t enumeratedCount = requireModuleBytes / static_cast<std::uint32_t>(sizeof(HMODULE));

    for (std::uint32_t i = 0; i < enumeratedCount; i++) {
        WCHAR Name[MAX_PATH];

        if (!K32GetModuleFileNameExW(hProcess, Modules[i], Name, MAX_PATH)) {
            continue;
        }

        if (!_wcsicmp(wcsrchr(Name, L'\\') + 1, wszModuleName)) {
            return K32GetModuleInformation(hProcess, Modules[i], ModuleInfo, sizeof(MODULEINFO));
        }
    }

    return false;
}

bool WriteImagesToDisk(_In_ PDUMPER pDumper) {
    for (const auto &target: pDumper->DumpTargets) {
        if (target.lpLocalBuffer && target.dwLocalBufferSize != 0) {
            info("writing image %ls (%llu bytes) to disk...", target.wszModuleName, target.dwLocalBufferSize);
            if (!WriteImageToDisk(pDumper, reinterpret_cast<unsigned char *>(target.lpLocalBuffer),
                                  target.dwLocalBufferSize, target.wszModuleName))
                return false;
        }
    }

    return true;
}

bool
WriteImageToDisk(_In_ PDUMPER Dumper, _In_ PBYTE Buffer, _In_ SIZE_T Size, _In_ const wchar_t *wszModuleName) {
    WCHAR Path[MAX_PATH];
    WCHAR Extension[MAX_PATH];

    //
    // Extract the file extension from the process name
    //
    if (const wchar_t *wszDotPosition = wcsrchr(wszModuleName, L'.'); wszDotPosition != nullptr) {
        wcscpy_s(Extension, MAX_PATH, wszDotPosition);
    }

    //
    // Check if the output directory exists, create it if not
    //
    if (!std::filesystem::exists(Dumper->OutputPath) && (
            !CreateDirectoryW(Dumper->OutputPath, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)) {
        error("Failed to create output directory: %ws", Dumper->OutputPath);

        return FALSE;
    }

    //
    // Check if the -t argument is passed and add the timestamp to the file name
    //
    if (Dumper->UseTimestamp) {
        //
        // Get the current time
        //
        const auto t = time(nullptr);
        tm timeInformation{};
        localtime_s(&timeInformation, &t);

        //
        // Format the timestamp as YYYY-MM-DD
        //
        WCHAR Timestamp[16];
        wcsftime(Timestamp, sizeof(Timestamp) / sizeof(wchar_t), L"%Y-%m-%d", &timeInformation);

        //
        // Construct the output file path with timestamp
        //
        swprintf(Path, MAX_PATH, L"%s\\%s_%s%s", Dumper->OutputPath, wszModuleName, Timestamp, Extension);
    } else {
        //
        // If no timestamp, use the regular format
        //
        swprintf(Path, MAX_PATH, L"%s\\%s", Dumper->OutputPath, wszModuleName);
    }

    //
    // Open the file for writing
    //
    HANDLE hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    //
    // Write the image to the file
    //
    std::size_t bytesWritten;
    if (!WriteFile(hFile, Buffer, Size, reinterpret_cast<unsigned long *>(&bytesWritten), nullptr)) {
        CloseHandle(hFile);
        return FALSE;
    }

    info("Successfully dumped image to disk (path: %ws)", Path);

    //
    // Close the file handle
    //
    CloseHandle(hFile);

    return TRUE;
}

static bool
BuildInitialImage(_In_ PDUMPER pDumper, const MODULEINFO &target, _Out_ PBYTE *pBuffer) {
    // Allocate the buffer to store the image.
    *pBuffer = new unsigned char[target.SizeOfImage];

    memset(*pBuffer, 0, target.SizeOfImage);

    //
    // The initial image will only contain the PE headers. This is the first memory region of the target process.
    //
    const auto targetBaseAddress = target.lpBaseOfDll;

    MEMORY_BASIC_INFORMATION memoryInfo;

    if (!VirtualQueryEx(pDumper->hProcess, targetBaseAddress, &memoryInfo, sizeof(memoryInfo))) {
        error("Failed to query memory region at 0x%p", targetBaseAddress);
        return false;
    }

    if (const NTSTATUS ntStatus = NtReadVirtualMemory(pDumper->hProcess, targetBaseAddress, *pBuffer,
                                                      memoryInfo.RegionSize,
                                                      nullptr); static_cast<NTSTATUS>(ntStatus) < 0) {
        error("Failed to read memory region at 0x%p (0x%08X)", targetBaseAddress, ntStatus);
        return false;
    }

    info("Built initial image of target process (0x%p)", targetBaseAddress);
    return true;
}

static BOOL WINAPI
CtrlHandler(const DWORD fdwCtrlType) {
    if (CTRL_C_EVENT == fdwCtrlType) {
        g_bTerminateCurrentTask = true;
        return true;
    }

    return false;
}
