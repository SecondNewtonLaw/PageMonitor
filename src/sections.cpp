#include "sections.hpp"

#include <future>
#include <vector>

#include "syscalls.hpp"
#include "out.hpp"

#define ALIGN_UP(x, align) (((x) + ((align)-1)) & ~((align)-1))

_Success_(return)

static BOOL
IsPossiblyEncrypted(_In_ PIMAGE_SECTION_HEADER SectionHeader);

_Success_(return)

static BOOL
DecryptSection(_In_ PDUMPER Dumper, const MODULEINFO &moduleinfo, _In_ PIMAGE_SECTION_HEADER SectionHeader,
               _In_ PBYTE ImageBase);

// =====================================================================================================================
// Public functions
// =====================================================================================================================

bool ResolveSections(_In_ PDUMPER pDumper, const MODULEINFO &moduleinfo, _In_ PBYTE *OriginalImage) {
    //
    // Ensure that the original image is not NULL.
    //
    if (nullptr == OriginalImage)
        return false;

    //
    // Get the base of the image.
    //
    auto ImageBase = *OriginalImage;

    //
    // Get all the headers.
    //
    const auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
    auto NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, ImageBase, DosHeader->e_lfanew);
    const auto OptionalHeader = &NtHeaders->OptionalHeader;
    auto SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

    //
    // Loop through all the sections.
    //

    /*
     *  We must sort the sections between encrypted and decrypted, then we must first read the decrypted sections first before proceeding.
     *  This ensures our image is valid from the get-go, only permitting issues (i.e: process crash) on the encrypted image.
     */

    struct SectionInformation {
        void *rpSectionBegin;
        void *rpSectionEnd;
        const char *szSectionName;
        PIMAGE_SECTION_HEADER pSectionHeader;
    };

    std::vector<SectionInformation> EncryptedSections{};

    for (auto i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, SectionHeader++) {
        //
        // Realign the virtual size of the section.
        //
        SectionHeader->Misc.VirtualSize =
                ALIGN_UP(SectionHeader->Misc.VirtualSize, NtHeaders->OptionalHeader.SectionAlignment);

        //
        // Calculate the base address of the section.
        //
        const auto sectionBaseAddress = RVA2VA(PVOID, OptionalHeader->ImageBase, SectionHeader->VirtualAddress);

        //
        // If the section is possibly encrypted, then we will decrypt it.
        //

        SectionInformation sectionInformation{};

        sectionInformation.rpSectionBegin = sectionBaseAddress;
        sectionInformation.rpSectionEnd = reinterpret_cast<void *>(
            SectionHeader->SizeOfRawData + reinterpret_cast<std::uintptr_t>(sectionBaseAddress));
        sectionInformation.szSectionName = reinterpret_cast<const char *>(SectionHeader->Name);
        sectionInformation.pSectionHeader = SectionHeader;

        if (lstrcmpA(sectionInformation.szSectionName, ".reloc") == 0) {
            warn("Skipping .reloc at 0x%p section (cannot be dumped)", sectionBaseAddress);
            continue;
        }

        if (IMAGE_SCN_CNT_CODE & SectionHeader->Characteristics == IMAGE_SCN_CNT_CODE) {
            warn("Declaring code segment '%s' at 0x%p section as R-X (If not marked already)", SectionHeader->Name,
                 sectionBaseAddress);

            if ((SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE) {
                warn("Declaring segment '%s' at 0x%p section as EXECUTE (Not marked)", SectionHeader->Name,
                     sectionBaseAddress);
                SectionHeader->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
            }

            if ((SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SCN_MEM_READ) {
                warn("Declaring segment '%s' at 0x%p section as READ (Not marked)", SectionHeader->Name,
                     sectionBaseAddress);
                SectionHeader->Characteristics |= IMAGE_SCN_MEM_READ;
            }
        }

        info("Assuming section %s at 0x%p to be ENCRYPTED", SectionHeader->Name, sectionBaseAddress);

        EncryptedSections.push_back(sectionInformation);
    }

    std::vector<std::future<std::pair<bool, const char *> > > futures{};

    for (const auto &encryptedSection: EncryptedSections) {
        futures.push_back(std::async(std::launch::async, [&moduleinfo, ImageBase, &encryptedSection, pDumper]() {
            return std::pair{
                pDumper->DecryptionFactor && DecryptSection(pDumper, moduleinfo, encryptedSection.pSectionHeader,
                                                            ImageBase),
                encryptedSection.szSectionName
            };
        }));
    }

    while (!futures.empty()) {
        for (auto it = futures.begin(); it != futures.end();) {
            if (const auto result = it->wait_for(std::chrono::milliseconds{1000});
                result == std::future_status::timeout) {
                ++it;
                continue; // Skip check.
            }

            if (const auto [success, sectionName] = it->get(); success) {
                info("decrypted section %s successfully [(Unknown percentage decrypted)]", sectionName);
            } else {
                warn("failed to decrypt section %s to completion successfully", sectionName);
            }

            it = futures.erase(it);
        }
    }

    return true;
}

// =====================================================================================================================
// Private functions
// =====================================================================================================================

_Success_(return)

static BOOL IsExecutableSegment(_In_ PIMAGE_SECTION_HEADER SectionHeader) {
    return (IMAGE_SCN_CNT_CODE & SectionHeader->Characteristics) == IMAGE_SCN_CNT_CODE;
}


std::mutex __decrypt_fixer_lock{};

_Success_(return)

static BOOL
DecryptSection(_In_ PDUMPER Dumper, const MODULEINFO &moduleinfo, _In_ PIMAGE_SECTION_HEADER SectionHeader,
               _In_ PBYTE ImageBase) {
    MEMORY_BASIC_INFORMATION MemoryInfo{};

    const auto szSectionName = reinterpret_cast<char *>(SectionHeader->Name);

    //
    // If this section is not named ".text" then the decryption factor is not applied.
    //
    std::uint32_t decryptedPageCount = 0;
    const std::uintptr_t TotalPageCount = SectionHeader->SizeOfRawData / PAGE_SIZE;
    const std::uint32_t PagesToDecrypt = TotalPageCount * (!lstrcmpA(szSectionName, ".text")
                                                               ? Dumper->DecryptionFactor
                                                               : 1.0f);
    struct PageInformation {
        void *address;
        std::uintptr_t pageIndex;
        std::uintptr_t size;
    };
    std::vector<PageInformation> dumpedPagesInformation{};
    std::vector<std::uintptr_t> EncryptedPagesIndex{};

    for (std::uintptr_t pageIndex = 0; pageIndex < TotalPageCount; ++pageIndex)
        EncryptedPagesIndex.push_back(pageIndex); // Build list.

    while (EncryptedPagesIndex.size() > (TotalPageCount - PagesToDecrypt) && !g_bTerminateCurrentTask) {
        for (auto start = EncryptedPagesIndex.begin(); start != EncryptedPagesIndex.end();) {
            if (DWORD exitCode; GetExitCodeProcess(Dumper->hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                warn("The target has been closed! Dump may be incomplete!");
                g_bTerminateCurrentTask = true;
                break;
            }

            // Calculate the base address of the current page.
            const auto currentPageRva = *start * PAGE_SIZE;
            const auto rpBaseAddress = RVA2VA(PVOID, moduleinfo.lpBaseOfDll,
                                              SectionHeader->VirtualAddress + currentPageRva);
            const auto pAlignedBuffer = RVA2VA(PBYTE, ImageBase, SectionHeader->PointerToRawData + currentPageRva);

            if (Dumper->ignoreVmp0Section && lstrcmpA(szSectionName, ".vmp0") == 0) {
                debug("Skipping page 0x%p due to being .vmp0 which slows down analysis. (Can be disabled in options)",
                      rpBaseAddress);
                memset(pAlignedBuffer, 0xCC, PAGE_SIZE);
                ++start;
                continue;
            }

            // Query mem info.
            if (!VirtualQueryEx(Dumper->hProcess, rpBaseAddress, &MemoryInfo, sizeof(MemoryInfo)))
                continue;

            // If the page is NO_ACCESS, then we will skip it, as it is encrypted.
            if (MemoryInfo.Protect & PAGE_NOACCESS) {
                /*
                 *  0xCC -> INT3, leads to faster decompiltion, breaks some functions.
                 *  0x90 -> NOP, leads to SUPER slow decompilation due to functions being weird, may break some functions.
                 */
                memset(pAlignedBuffer, 0xCC, PAGE_SIZE);
                ++start; // Move to next page
                continue;
            }

            std::uintptr_t read{};

            if (const NTSTATUS ntReadVirtualMemoryStatus = NtReadVirtualMemory(
                Dumper->hProcess, rpBaseAddress, pAlignedBuffer, PAGE_SIZE,
                &read); static_cast<NTSTATUS>(ntReadVirtualMemoryStatus) < 0) {
                error("Failed to read memory region at 0x%p (0x%08X)", rpBaseAddress, ntReadVirtualMemoryStatus);
                return false;
            }


            if (read != PAGE_SIZE) {
                warn("Possible incomplete read of a page %llu, maybe re-encrypted during read? Dropping result.",
                     *start);
                continue;
            }

            //
            // Mark the page as decrypted.
            //
            decryptedPageCount++;

            if (Dumper->DecryptionFactor > FLT_MIN) {
                info(
                    "Decrypted page in %s at 0x%p (%lu/%lu = %.2f%%)",
                    szSectionName,
                    rpBaseAddress,
                    decryptedPageCount,
                    PagesToDecrypt,
                    static_cast<float>(decryptedPageCount) / PagesToDecrypt * 100.0f);
            }

            dumpedPagesInformation.emplace_back(PageInformation
                {
                    pAlignedBuffer, *start, PAGE_SIZE
                });

            start = EncryptedPagesIndex.erase(start);
        }
        _mm_pause(); // Rest up CPU (:pray:)
    }

    if (IsExecutableSegment(SectionHeader) && !(Dumper->ignoreVmp0Section && lstrcmpA(szSectionName, ".vmp0") == 0)) {
        info("Patching int3 instructions that break analysis...");

        const auto ModifiesProcessorFlags = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_TEST == insn ||
                   ::x86_insn::X86_INS_CMP == insn ||
                   ::x86_insn::X86_INS_CMPPD == insn ||
                   ::x86_insn::X86_INS_CMPPS == insn ||
                   ::x86_insn::X86_INS_CMPSB == insn ||
                   ::x86_insn::X86_INS_CMPSD == insn ||
                   ::x86_insn::X86_INS_CMPSQ == insn ||
                   ::x86_insn::X86_INS_CMPSS == insn ||
                   ::x86_insn::X86_INS_CMPSW == insn ||
                   ::x86_insn::X86_INS_CMPXCHG == insn ||
                   ::x86_insn::X86_INS_CMPXCHG8B == insn ||
                   ::x86_insn::X86_INS_CMPXCHG16B == insn;
        };
        const auto IsInterrupt = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_INT == insn ||
                   ::x86_insn::X86_INS_INT1 == insn ||
                   ::x86_insn::X86_INS_INT3 == insn ||
                   ::x86_insn::X86_INS_INTO == insn ||
                   ::x86_insn::X86_INS_SYSCALL == insn;
        };
        const auto IsReturn = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_RET == insn ||
                   ::x86_insn::X86_INS_RETF == insn ||
                   ::x86_insn::X86_INS_RETFQ == insn;
        };
        const auto IsCall = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_CALL == insn;
        };
        const auto IsJump = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_JMP == insn ||
                   ::x86_insn::X86_INS_JAE == insn ||
                   ::x86_insn::X86_INS_JA == insn ||
                   ::x86_insn::X86_INS_JBE == insn ||
                   ::x86_insn::X86_INS_JB == insn ||
                   ::x86_insn::X86_INS_JCXZ == insn ||
                   ::x86_insn::X86_INS_JECXZ == insn ||
                   ::x86_insn::X86_INS_JE == insn ||
                   ::x86_insn::X86_INS_JGE == insn ||
                   ::x86_insn::X86_INS_JG == insn ||
                   ::x86_insn::X86_INS_JLE == insn ||
                   ::x86_insn::X86_INS_JL == insn ||
                   ::x86_insn::X86_INS_JNE == insn ||
                   ::x86_insn::X86_INS_JNO == insn ||
                   ::x86_insn::X86_INS_JNP == insn ||
                   ::x86_insn::X86_INS_JNS == insn ||
                   ::x86_insn::X86_INS_JO == insn ||
                   ::x86_insn::X86_INS_JP == insn ||
                   ::x86_insn::X86_INS_JRCXZ == insn ||
                   ::x86_insn::X86_INS_JS == insn;
        };
        const auto insn = cs_malloc(Dumper->capstoneHandle);
        for (const auto &targetPage: dumpedPagesInformation) {
            auto pageSize = static_cast<std::size_t>(PAGE_SIZE);
            auto startChunk = static_cast<const std::uint8_t *>(targetPage.address);
            auto currentAddress = reinterpret_cast<std::uintptr_t>(targetPage.address);

            auto PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_NOP;

            while (cs_disasm_iter(Dumper->capstoneHandle, &startChunk, &pageSize,
                                  &currentAddress, insn)) {
                /*
                 *  To determine if an INT3 is ignorable, we must first consider that if the instruction coming before an int3 is CALL or an
                 *  instruction which causes any kind of branching, this means the instruction is LIKELY to mark the end of the function
                 *
                 *  OpCodes like CALL, JMP and RET may delimit functions endings if they come before INT3, but INT3 after other instructions are
                 *  traps placed by obfuscation tools or just plain garbage we read from the proc, but bad, lol.
                 */

                constexpr auto interrupt = unsigned char{0xCC};

                if ((!IsJump(PREVIOUS_INSTRUCTION) && !IsReturn(PREVIOUS_INSTRUCTION) && !IsInterrupt(
                         PREVIOUS_INSTRUCTION) && IsInterrupt(
                         static_cast<::x86_insn>(insn->id)) && memcmp(
                         reinterpret_cast<void *>(insn->address + insn->size),
                         &interrupt, 1) != 0)
                    || (IsCall(PREVIOUS_INSTRUCTION) || ModifiesProcessorFlags(PREVIOUS_INSTRUCTION)) && IsInterrupt(
                        static_cast<::x86_insn>(insn->id))) {
                    /*
                     *  The next instruction is not an interrupt, the previous instruction was not a jump (Which would denote an end in an execution block)
                     *  - Implementation note:
                     *      - Hyperion appears to be (IN PURPOSE) modifying CPU flags before interrupts, possibly relating to tripping
                     *        their IC and passing the Interrupt and ignoring it if such is the case that the flag is set?
                     *      - Hyperion appears to sometimes use the INT3 to perform return-based programming, possibly to break analysis (?)
                     */
                    debug(
                        "PATCHED ORPHAN INTERRUPT (POSSIBLY A FAKE INSTRUCTION!) @ %p",
                        reinterpret_cast<void *>(insn->address));

                    memset(reinterpret_cast<void *>(insn->address), 0x90, insn->size); // Address is canonical.

                    if (IsCall(PREVIOUS_INSTRUCTION) && IsInterrupt(static_cast<::x86_insn>(insn->id))) {
                        /*
                         *  Due to this function likely ending here, we must replace the INT3 with a ret instruction.
                         */
                        debug(
                            "PATCHED POSSIBLE INT3-BASED RETURN @ %p", reinterpret_cast<void *>(insn->address));
                        memset(reinterpret_cast<void *>(insn->address), 0xC3, 1);
                    }

                    if ((ModifiesProcessorFlags(PREVIOUS_INSTRUCTION)) && IsInterrupt(
                            static_cast<::x86_insn>(insn->id))) {
                        auto addy = insn->address;
                        while (memcmp(reinterpret_cast<void *>(++addy), &interrupt, 1) == 0) {
                            debug(
                                "PATCHED FOLLOWING INTERRUPTS THAT WERE MISLEADING ANALYSIS @ %p.",
                                reinterpret_cast<void *>(insn->address));
                            memset(reinterpret_cast<void *>(addy), 0x90, 1);
                        }
                    }

                    PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_NOP;
                    continue;
                }

                PREVIOUS_INSTRUCTION = static_cast<::x86_insn>(insn->id);
            }
        }
        cs_free(insn, 1);
    } else {
        info("section was determined to not be an executable section; skipping patching int3.");
    }

    //g_bTerminateCurrentTask = false; We want to stop but once we terminate one task we will not want to stop? Which idiot wrote this code
    return true;
}
