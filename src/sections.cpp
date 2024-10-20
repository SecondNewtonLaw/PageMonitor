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
    //
    // If the section is named ".text" then it is possibly encrypted.
    //
    return IMAGE_SCN_MEM_EXECUTE & SectionHeader->Characteristics;
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

    if (IsExecutableSegment(SectionHeader)) {
        info("cleaning up executable section");

        const auto insn = cs_malloc(Dumper->capstoneHandle);
        for (const auto &targetPage: dumpedPagesInformation) {
            auto pageSize = static_cast<std::size_t>(PAGE_SIZE);
            auto startChunk = static_cast<const std::uint8_t *>(targetPage.address);
            auto currentAddress = reinterpret_cast<std::uintptr_t>(targetPage.address);

            auto PREVIOUS_INSTRUCTIONSIZE = 0ll;
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

                const auto isPreviousInstructionNOP = PREVIOUS_INSTRUCTION == ::x86_insn::X86_INS_NOP;
                const auto isPreviousInstructionINT3 = PREVIOUS_INSTRUCTION == ::x86_insn::X86_INS_INT3;
                const auto isPreviousInstructionReturnOrCall =
                        PREVIOUS_INSTRUCTION == ::x86_insn::X86_INS_CALL || PREVIOUS_INSTRUCTION ==
                        ::x86_insn::X86_INS_RET || PREVIOUS_INSTRUCTION == ::x86_insn::X86_INS_JMP;

                if (isPreviousInstructionNOP && insn->id == ::x86_insn::X86_INS_INT3) {
                    info(
                        "FIXING INT3->>NOP miss-convert in decrypted insn @ %p", startChunk);
                    *const_cast<std::uint8_t *>(startChunk - insn->size) = 0xCC;

                    PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_INT3;
                    PREVIOUS_INSTRUCTIONSIZE = insn->size;
                    continue;
                }

                if ((isPreviousInstructionINT3 || isPreviousInstructionReturnOrCall) && insn->id ==
                    ::x86_insn::X86_INS_INT3) {
                    // Previous is a RET or a CALL, current is INT3, skip.
                    // Possibly a chain of insns that are INT3 and delimit function end and start, they do not need any replacement.
                    PREVIOUS_INSTRUCTION = static_cast<::x86_insn>(insn->id);
                    PREVIOUS_INSTRUCTIONSIZE = insn->size;
                    continue;
                }

                if (!isPreviousInstructionReturnOrCall && !isPreviousInstructionINT3 && !isPreviousInstructionNOP &&
                    insn->id == ::x86_insn::X86_INS_INT3) {
                    info(
                        "Replacing INT3 to NOP from decrypted insn @ %p", startChunk);
                    *const_cast<std::uint8_t *>(startChunk - insn->size) = 0x90;

                    PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_NOP;
                    PREVIOUS_INSTRUCTIONSIZE = insn->size;
                    continue;
                }


                PREVIOUS_INSTRUCTION = static_cast<::x86_insn>(insn->id);
                PREVIOUS_INSTRUCTIONSIZE = insn->size;
            }
        }
        cs_free(insn, 1);
    }

    g_bTerminateCurrentTask = false;
    return true;
}
