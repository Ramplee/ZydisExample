#pragma once

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "structs.hpp"
#include "logging.hpp"

namespace Pe {

inline std::vector<std::uint8_t> LoadFile(const std::string& Path) {
    std::ifstream File(Path, std::ios::binary);
    if (!File) {
        LogError("Failed to open file: %s", Path.c_str());
        throw std::runtime_error("Failed to open file " + Path);
    }

    std::vector<std::uint8_t> Data((std::istreambuf_iterator<char>(File)), std::istreambuf_iterator<char>());
    LogInfo("Loaded file %s (%zu bytes)", Path.c_str(), Data.size());
    return Data;
}

inline std::uint32_t GetPageRva(const std::vector<std::uint8_t>& FileBytes) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Invalid DOS header: expected 0x%X, got 0x%X", IMAGE_DOS_SIGNATURE, Dos->e_magic);
        throw std::runtime_error("Invalid DOS header");
    }

    const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(FileBytes.data() + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) {
        LogError("Invalid NT headers: expected 0x%X, got 0x%X", IMAGE_NT_SIGNATURE, Nt->Signature);
        throw std::runtime_error("Invalid NT headers");
    }

    const IMAGE_SECTION_HEADER* Section = IMAGE_FIRST_SECTION(Nt);
    for (int I = 0; I < Nt->FileHeader.NumberOfSections; ++I, ++Section) {
        const std::string Name(reinterpret_cast<const char*>(Section->Name), 8);
        LogInfo("Checking section: %s", Name.c_str());

        if (Name.find("PAGE") != std::string::npos) {
            LogInfo("Found PAGE section at RVA 0x%X", Section->VirtualAddress);
            return Section->VirtualAddress;
        }
    }

    LogWarn("PAGE section not found in file");
    throw std::runtime_error("PAGE section not found");
}

inline std::uint64_t GetImageBase(const std::vector<std::uint8_t>& FileBytes) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Invalid DOS header: expected 0x%X, got 0x%X", IMAGE_DOS_SIGNATURE, Dos->e_magic);
        throw std::runtime_error("Invalid DOS header");
    }

    const auto* Nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(FileBytes.data() + Dos->e_lfanew);
    if (Nt64->Signature != IMAGE_NT_SIGNATURE) {
        LogError("Invalid NT headers: expected 0x%X, got 0x%X", IMAGE_NT_SIGNATURE, Nt64->Signature);
        throw std::runtime_error("Invalid NT headers");
    }
    if (Nt64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        LogError("Not a PE64 image, magic: 0x%X", Nt64->OptionalHeader.Magic);
        throw std::runtime_error("Not a PE64 image");
    }

    LogInfo("ImageBase: 0x%llx", Nt64->OptionalHeader.ImageBase);
    return Nt64->OptionalHeader.ImageBase;
}

inline std::uintptr_t PatternScanInRange(std::uintptr_t Base, std::size_t Range, const char* PatternBytes,
                                          const char* Mask) {
    const auto MatchChunk = [](const char* Haystack, const char* Pat, const char* MaskStr) -> bool {
        for (; *MaskStr; ++Haystack, ++Pat, ++MaskStr) {
            if (*MaskStr == 'x' && *Haystack != *Pat) {
                return false;
            }
        }
        return true;
    };

    const std::size_t Need = std::strlen(Mask);
    if (Range < Need) {
        return 0;
    }
    Range -= Need;

    for (std::size_t I = 0; I <= Range; ++I) {
        if (MatchChunk(reinterpret_cast<const char*>(Base) + I, PatternBytes, Mask)) {
            return Base + I;
        }
    }
    return 0;
}

// Scans executable sections of a PE image in memory (or raw file buffer laid out like on disk)
inline std::uintptr_t PatternScan(std::uintptr_t ImageBase, const char* PatternBytes, const char* Mask) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ImageBase);
    const auto* Headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ImageBase + Dos->e_lfanew);
    const IMAGE_SECTION_HEADER* Sections = IMAGE_FIRST_SECTION(Headers);

    for (unsigned I = 0; I < Headers->FileHeader.NumberOfSections; ++I) {
        const IMAGE_SECTION_HEADER& Sec = Sections[I];
        if (Sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            const std::uintptr_t SectBase = ImageBase + Sec.PointerToRawData;
            const std::size_t SectSize = static_cast<std::size_t>(Sec.SizeOfRawData);
            const std::uintptr_t Hit = PatternScanInRange(SectBase, SectSize, PatternBytes, Mask);
            if (Hit != 0) {
                return Hit;
            }
        }
    }

    return 0;
}

inline bool FileOffsetToRvaAndSection(const std::vector<std::uint8_t>& FileBytes, std::uint64_t FileOff,
                                      std::uint32_t& RvaOut, char SectionNameOut[9]) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(FileBytes.data() + Dos->e_lfanew);
    if (!Nt || Nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_SECTION_HEADER* Sec = IMAGE_FIRST_SECTION(Nt);
    for (int I = 0; I < Nt->FileHeader.NumberOfSections; ++I, ++Sec) {
        const std::uint32_t Raw = Sec->PointerToRawData;
        const std::uint32_t Size = Sec->SizeOfRawData;
        if (FileOff >= Raw && FileOff < static_cast<std::uint64_t>(Raw) + Size) {
            RvaOut = static_cast<std::uint32_t>((FileOff - Raw) + Sec->VirtualAddress);
            std::memset(SectionNameOut, 0, 9);
            std::memcpy(SectionNameOut, Sec->Name, 8);
            SectionNameOut[8] = '\0';
            return true;
        }
    }
    return false;
}

inline bool RvaToFileOffset(const std::vector<std::uint8_t>& FileBytes, std::uint32_t Rva,
                            std::uint32_t& RawOut, char SectionNameOut[9] = nullptr) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(FileBytes.data() + Dos->e_lfanew);
    if (!Nt || Nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const IMAGE_SECTION_HEADER* Sec = IMAGE_FIRST_SECTION(Nt);
    for (int I = 0; I < Nt->FileHeader.NumberOfSections; ++I, ++Sec) {
        const std::uint32_t Va = Sec->VirtualAddress;
        const std::uint32_t Vsz = Sec->Misc.VirtualSize ? Sec->Misc.VirtualSize : Sec->SizeOfRawData;
        if (Rva >= Va && Rva < Va + Vsz) {
            RawOut = Sec->PointerToRawData + (Rva - Va);
            if (SectionNameOut) {
                std::memset(SectionNameOut, 0, 9);
                std::memcpy(SectionNameOut, Sec->Name, 8);
                SectionNameOut[8] = '\0';
            }
            return true;
        }
    }
    return false;
}

inline bool FindFunctionRangeRva(const std::vector<std::uint8_t>& FileBytes, std::uint32_t RvaQuery,
                                 std::uint32_t& BeginRvaOut, std::uint32_t& EndRvaOut) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(FileBytes.data() + Dos->e_lfanew);
    if (!Nt || Nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& Dir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (Dir.VirtualAddress == 0 || Dir.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
        return false;
    }

    std::uint32_t ExcRaw = 0;
    if (!RvaToFileOffset(FileBytes, Dir.VirtualAddress, ExcRaw)) {
        return false;
    }

    const std::size_t Count = Dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    const auto* Funcs = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(FileBytes.data() + ExcRaw);
    for (std::size_t I = 0; I < Count; ++I) {
        const IMAGE_RUNTIME_FUNCTION_ENTRY& F = Funcs[I];
        if (F.BeginAddress <= RvaQuery && RvaQuery < F.EndAddress) {
            BeginRvaOut = F.BeginAddress;
            EndRvaOut = F.EndAddress;
            return true;
        }
    }
    return false;
}

inline Structs::SectionInfo GetPageSectionInfo(const std::vector<std::uint8_t>& FileBytes) {
    const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(FileBytes.data());
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Invalid DOS header: expected 0x%X, got 0x%X", IMAGE_DOS_SIGNATURE, Dos->e_magic);
        throw std::runtime_error("Invalid DOS header");
    }

    const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(FileBytes.data() + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) {
        LogError("Invalid NT headers: expected 0x%X, got 0x%X", IMAGE_NT_SIGNATURE, Nt->Signature);
        throw std::runtime_error("Invalid NT headers");
    }

    const IMAGE_SECTION_HEADER* Sec = IMAGE_FIRST_SECTION(Nt);
    for (int I = 0; I < Nt->FileHeader.NumberOfSections; ++I, ++Sec) {
        const std::string Name(reinterpret_cast<const char*>(Sec->Name), 8);
        LogInfo("Checking section %s", Name.c_str());

        if (Name.find("PAGE") != std::string::npos) {
            LogInfo("Found PAGE section at RVA 0x%X, Raw 0x%X, Size 0x%X", Sec->VirtualAddress,
                    Sec->PointerToRawData, Sec->SizeOfRawData);

            Structs::SectionInfo Info{};
            Info.Rva = Sec->VirtualAddress;
            Info.Raw = Sec->PointerToRawData;
            Info.RawSize = Sec->SizeOfRawData;
            std::memset(Info.Name, 0, sizeof(Info.Name));
            std::memcpy(Info.Name, Sec->Name, 8);
            Info.Name[8] = '\0';
            return Info;
        }
    }

    LogWarn("PAGE section not found in file");
    throw std::runtime_error("PAGE section not found");
}

} // namespace Pe
