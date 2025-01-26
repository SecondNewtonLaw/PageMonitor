#include <Windows.h>
#include <shellapi.h>

#include "dumper.hpp"
#include "out.hpp"

//
// Prints the usage of the application.
//
static VOID
Usage();

//
// Enables a token privilege for the current process.
//
_Success_(return)

static BOOL
EnableTokenPrivilege(_In_ LPCTSTR Privilege);

//
// Macro that helps define command line arguments.
//
#define CHECK_ARGUMENTS() \
    if (i + 1 >= nArgs) \
    { \
        error("Missing argument for option %ws", szArglist[i]); \
        Usage(); \
        return EXIT_FAILURE; \
    }

//
// The entry point of the application. This is where command-line arguments are parsed and the dumper is launched. Refer
// to the available options below:
//
//  Options:
//      * -p <name> - The name of the target process to dump.
//      * -o <path> - The output directory where the dump will be saved (default: current directory).
//      * -t - Include a timestamp in the filename (e.g., program_2024-09-08.exe).
//      * --decrypt <factor> - Amount (%) of no access pages to have decrypted before dumping
//      * -M <name> - The name of the target module to dump, if not present the process PE will be dumped.
//  Flags:
//      * -D - Enable debug mode.
//
int
_cdecl main() {
    int nArgs{};
    const wchar_t *wszTargetModule = nullptr;
    DUMPER Dumper{};
    Dumper.ignoreVmp0Section = TRUE;

    wchar_t * *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

    if (!szArglist) {
        error("CommandLineToArgvW failed with error %lu", GetLastError());
        return EXIT_FAILURE;
    }

    float fDecryptionFactor = 1.0f;

    bool bIsDebugMode = false;
    bool bUseTimeStamp = false;

    const wchar_t *wszTargetName = nullptr;
    const wchar_t *outputPath = const_cast<wchar_t *>(L"./dump_out");

    for (int i = 1; i < nArgs; i++) {
        if (wcsstr(szArglist[i], L"-") == nullptr)
            continue;

        if (lstrcmpW(szArglist[i], L"--decrypt") == 0) {
            CHECK_ARGUMENTS();

            fDecryptionFactor = wcstof(szArglist[i + 1], nullptr);
            i++;

            if (fDecryptionFactor < 0.0f || fDecryptionFactor > 1.0f) {
                error("Invalid value for --decrypt flag. Must be between 0.0 and 1.0");
                Usage();
                return EXIT_FAILURE;
            }
        } else if (lstrcmpW(szArglist[i], L"-o") == 0) {
            CHECK_ARGUMENTS();

            outputPath = szArglist[i + 1];
            i++;
        } else if (lstrcmpW(szArglist[i], L"-p") == 0) {
            CHECK_ARGUMENTS();

            wszTargetName = szArglist[i + 1];
            i++;
        } else if (lstrcmpW(szArglist[i], L"-M") == 0) {
            CHECK_ARGUMENTS();
            wszTargetModule = szArglist[i + 1];
            i++;
        } else if (lstrcmpW(szArglist[i], L"-D") == 0) {
            bIsDebugMode = TRUE;
        } else if (lstrcmpW(szArglist[i], L"-t") == 0) {
            bUseTimeStamp = TRUE;
        } else if (lstrcmpW(szArglist[i], L"--ignore-vmp") == 0) {
            const auto providedValue = szArglist[i + 1];
            if (lstrcmpiW(providedValue, L"y") == 0) {
                Dumper.ignoreVmp0Section = TRUE;
            } else if (lstrcmpiW(providedValue, L"n") == 0) {
                Dumper.ignoreVmp0Section = FALSE;
            }
        } else {
            error("Unknown option: %ws", szArglist[i]);
            Usage();
            return EXIT_FAILURE;
        }
    }

    if (!wszTargetName) {
        error("Missing argument for option -p");
        Usage();
        return EXIT_FAILURE;
    }

    //
    // Enable the SeDebugPrivilege.
    //
    if (bIsDebugMode && !EnableTokenPrivilege(SE_DEBUG_NAME)) {
        error("Failed to enable SeDebugPrivilege");
        return 1;
    }

    if (!DumperCreate(&Dumper, wszTargetName, wszTargetModule == nullptr ? L"main_image" : wszTargetModule, outputPath,
                      fDecryptionFactor,
                      bUseTimeStamp)) {
        return EXIT_FAILURE;
    }

    //
    // Dump the target process memory to disk.
    //
    if (!DumperDumpToDisk(&Dumper)) {
        return EXIT_FAILURE;
    }

    //
    // Destroys the dumper object.
    //
    return DumperDestroy(&Dumper);
}

VOID
Usage() {
    fprintf(stdout, "Usage: dumper [options] <pid>\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -p <name>            The name of the target process to dump.\n");
    fprintf(stdout, "  --ignore-vmp y/n      Determines if we should ignore .vmp0 section. (Defaults to yes)\n");
    fprintf(stdout, "  -o <path>            The output directory where the dump will be saved (default: \".\").\n");
    fprintf(
        stdout,
        "  -M <module name>     The name of the target module that has to be dumped from the target process or all to dump all modules and PE Image (defaults to the PE Image if not declared).\n");

    fprintf(stdout, "  -t                   Include a timestamp in the filename (e.g., program_2024-09-08.exe).\n");
    fprintf(
        stdout,
        "  --decrypt <factor>   Fraction of no access pages to have decrypted before dumping (Default: 1).\n");
    fprintf(stdout, "Flags:\n");
    fprintf(stdout, "  -D                   Enable debug mode (Default: false).\n");
}

_Success_(return)

static BOOL
EnableTokenPrivilege(_In_ LPCTSTR Privilege) {
    HANDLE Token;
    TOKEN_PRIVILEGES TokenPrivileges;

    Token = NULL;

    //
    // Zero out the token privileges structure.
    //
    ZeroMemory(&TokenPrivileges, sizeof(TOKEN_PRIVILEGES));

    //
    // Get a token for this process.
    //
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token)) {
        return FALSE;
    }

    //
    // Get the LUID for the privilege.
    //
    if (LookupPrivilegeValue(NULL, Privilege, &TokenPrivileges.Privileges[0].Luid)) {
        TokenPrivileges.PrivilegeCount = 1;
        TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        //
        // Set the privilege for this process.
        //
        return AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, 0, (PTOKEN_PRIVILEGES) NULL, 0);
    }

    return FALSE;
}
