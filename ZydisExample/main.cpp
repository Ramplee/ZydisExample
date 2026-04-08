#include "Common.hpp"

namespace {
constexpr std::string_view kDefaultFilePath = R"(C:\Program Files\Riot Vanguard\vgk.sys)";

struct PatternSignature {
    std::string_view Name;
    std::string_view PatternText;
};

void LogOperandOffsetsFromFormattedLine(const std::string& FormattedLine, std::uint64_t ImageBase,
                                        const std::string& Label) {
    static const std::regex AddrRegex(R"(\[0x([0-9A-Fa-f]+)\])");
    for (auto It = std::sregex_iterator(FormattedLine.begin(), FormattedLine.end(), AddrRegex);
         It != std::sregex_iterator(); ++It) {
        const std::uint64_t AbsAddr = std::stoull((*It)[1].str(), nullptr, 16);
        const std::uint64_t PeOffset = AbsAddr - ImageBase;
        std::printf("\033[32m    %s 0x%llX\n\033[0m", Label.c_str(),
                    static_cast<unsigned long long>(PeOffset));
    }
}

bool TryFindSignature(const std::vector<std::uint8_t>& FileBytes, const PatternSignature& Signature,
                      std::uint64_t& OutFileOffset) {
    const std::uintptr_t BufferBase = reinterpret_cast<std::uintptr_t>(FileBytes.data());

    std::string PatternBytes;
    std::string Mask;
    if (!Pattern::ParseWildcardText(std::string(Signature.PatternText), PatternBytes, Mask)) {
        LogWarn("Invalid signature pattern: %.*s", static_cast<int>(Signature.Name.size()), Signature.Name.data());
        return false;
    }

    const std::uintptr_t Match = Pe::PatternScan(BufferBase, PatternBytes.c_str(), Mask.c_str());
    if (Match == 0) {
        LogWarn("Signature not found: %.*s", static_cast<int>(Signature.Name.size()), Signature.Name.data());
        return false;
    }

    OutFileOffset = static_cast<std::uint64_t>(Match - BufferBase);
    return true;
}

void DecodeAndPrintMatch(const std::vector<std::uint8_t>& FileBytes, std::uint64_t ImageBase,
                         std::uint32_t InstructionFileOffset, const char SectionName[9],
                         const std::string& OperandLabel) {
    ZydisDecoder ZDecoder{};
    ZydisDecoderInit(&ZDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter Formatter{};
    ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    const std::uint32_t InsnRaw = InstructionFileOffset;
    const std::size_t BackRaw = (InsnRaw >= 16) ? static_cast<std::size_t>(InsnRaw - 16) : 0;
    const std::size_t EndRaw = std::min(FileBytes.size(), static_cast<std::size_t>(InsnRaw + 32));

    std::uint32_t BackRva = 0;
    char TmpSec[9]{};
    std::uint32_t MatchRva = 0;
    char MatchSec[9]{};
    if (!Pe::FileOffsetToRvaAndSection(FileBytes, InstructionFileOffset, MatchRva, MatchSec)) {
        return;
    }
    (void)MatchSec;

    if (!Pe::FileOffsetToRvaAndSection(FileBytes, static_cast<std::uint64_t>(BackRaw), BackRva, TmpSec)) {
        BackRva = (MatchRva >= (InsnRaw - static_cast<std::uint32_t>(BackRaw)))
                      ? MatchRva - static_cast<std::uint32_t>(InsnRaw - BackRaw)
                      : MatchRva;
    }

    std::uint64_t CurRva = BackRva;
    std::size_t CurRaw = BackRaw;

    ZydisDecodedInstruction Instr{};
    ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT]{};

    while (CurRaw < EndRaw) {
        const std::size_t MaxLen = std::min<std::size_t>(15, EndRaw - CurRaw);
        if (ZYAN_SUCCESS(
                ZydisDecoderDecodeFull(&ZDecoder, FileBytes.data() + CurRaw, MaxLen, &Instr, Ops))) {
            char Buffer[256]{};
            ZydisFormatterFormatInstruction(&Formatter, &Instr, Ops, Instr.operand_count, Buffer, sizeof(Buffer),
                                            ImageBase + CurRva, nullptr);

            if (CurRaw == InsnRaw) {
                LogInfo("  %s:%016llx  %s", SectionName, static_cast<unsigned long long>(CurRva), Buffer);
                LogOperandOffsetsFromFormattedLine(Buffer, ImageBase, OperandLabel);
                break;
            }
            CurRaw += Instr.length;
            CurRva += Instr.length;
        } else {
            ++CurRaw;
            ++CurRva;
        }
    }
}

int RunZydisSignatureScan() {
    const std::string InputFilePath(kDefaultFilePath);
    const std::vector<std::uint8_t> FileBytes = Pe::LoadFile(InputFilePath);
    const std::uint64_t ImageBase = Pe::GetImageBase(FileBytes);
    LogInfo("ImageBase: 0x%llx", ImageBase);

    static constexpr std::string_view FirstSigExample =
        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9";

    static constexpr std::string_view SecondSigExample =
        "E8 ? ? ? ? 48 8B ? ? ? ? ? 48 85 C0";

    static constexpr PatternSignature kSignatures[] = {
        { "FirstSigExample", FirstSigExample },
        { "SecondSigExample", SecondSigExample },
    };

    for (const PatternSignature& Signature : kSignatures) {
        std::uint64_t FileOffset = 0;
        if (!TryFindSignature(FileBytes, Signature, FileOffset)) {
            continue;
        }

        LogInfo("%.*s @ file offset 0x%llx", static_cast<int>(Signature.Name.size()), Signature.Name.data(),
                static_cast<unsigned long long>(FileOffset));

        std::uint32_t Rva = 0;
        char SectionName[9]{};
        if (Pe::FileOffsetToRvaAndSection(FileBytes, FileOffset, Rva, SectionName)) {
            LogInfo("Match %s:%016llx (VA 0x%llx)", SectionName, static_cast<unsigned long long>(Rva),
                    ImageBase + static_cast<std::uint64_t>(Rva));
        }

        DecodeAndPrintMatch(FileBytes, ImageBase, static_cast<std::uint32_t>(FileOffset), SectionName,
                            std::string(Signature.Name));
    }

    return 0;
}

} // namespace

int main() {
    int ExitCode = 0;
    try {
        ExitCode = RunZydisSignatureScan();
    } catch (const std::exception& Ex) {
        LogError("Exception: %s", Ex.what());
        ExitCode = 1;
    }

    std::puts("Press Enter to exit...");
    (void)std::getchar();
    return ExitCode;
}
