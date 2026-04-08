#pragma once

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstring>
#include <vector>

#include "pe.hpp"
#include "structs.hpp"

namespace Decoder {

namespace Detail {

inline std::vector<Structs::CiOptionCheck> ScanTestThenJz(const std::vector<std::uint8_t>& Bytes,
                                                          std::size_t StartRaw, std::size_t EndRaw,
                                                          std::uint64_t BaseRva) {
    ZydisDecoder ZydisDec{};
    ZydisDecoderInit(&ZydisDec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<Structs::CiOptionCheck> Patches;
    std::uint64_t RuntimeRva = BaseRva;
    std::size_t Offset = StartRaw;

    bool HasPrev = false;
    ZydisDecodedInstruction PrevInstr{};
    ZydisDecodedOperand PrevOps[ZYDIS_MAX_OPERAND_COUNT]{};

    auto CommitIfNextIsJz = [&](std::uint32_t MaskVal, std::size_t CurFileOffset, std::uint64_t CurRva) {
        ZydisDecodedInstruction NextInstr{};
        ZydisDecodedOperand NextOps[ZYDIS_MAX_OPERAND_COUNT]{};
        if (CurFileOffset >= EndRaw) {
            return;
        }
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ZydisDec, Bytes.data() + CurFileOffset, EndRaw - CurFileOffset,
                                                &NextInstr, NextOps))
            && NextInstr.mnemonic == ZYDIS_MNEMONIC_JZ) {
            Structs::CiOptionCheck Check{};
            Check.Rva = CurRva;
            Check.FileOffset = (CurRva - BaseRva) + StartRaw;
            Check.Mask = MaskVal;
            Check.JccOpcode = NextInstr.opcode;
            Patches.push_back(Check);
        }
    };

    while (Offset < EndRaw) {
        ZydisDecodedInstruction Instr{};
        ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT]{};

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&ZydisDec, Bytes.data() + Offset, EndRaw - Offset, &Instr, Ops))) {
            if (Instr.mnemonic == ZYDIS_MNEMONIC_TEST && Instr.operand_count >= 2) {
                if (Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    const auto MaskVal = static_cast<std::uint32_t>(Ops[1].imm.value.u);
                    const std::size_t NextFile = Offset + Instr.length;
                    const std::uint64_t NextRva = RuntimeRva + Instr.length;
                    CommitIfNextIsJz(MaskVal, NextFile, NextRva);
                } else if (Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                           && HasPrev) {
                    if (PrevInstr.mnemonic == ZYDIS_MNEMONIC_MOV && PrevInstr.operand_count >= 2) {
                        if (PrevOps[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                            && PrevOps[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                            && PrevOps[0].reg.value == Ops[1].reg.value) {
                            const auto MaskVal = static_cast<std::uint32_t>(PrevOps[1].imm.value.u);
                            const std::size_t NextFile = Offset + Instr.length;
                            const std::uint64_t NextRva = RuntimeRva + Instr.length;
                            CommitIfNextIsJz(MaskVal, NextFile, NextRva);
                        }
                    }
                }
            }

            HasPrev = true;
            PrevInstr = Instr;
            std::memcpy(PrevOps, Ops, sizeof(PrevOps));

            Offset += Instr.length;
            RuntimeRva += Instr.length;
        } else {
            HasPrev = false;
            ++Offset;
            ++RuntimeRva;
        }
    }

    return Patches;
}

} // namespace Detail

// Example: walk a PE section and find TEST … / JZ patterns (illustrative use of Zydis decode loop...)
inline std::vector<Structs::CiOptionCheck> ScanCiquery(const std::vector<std::uint8_t>& Bytes,
                                                       const Structs::SectionInfo& Page) {
    const std::size_t EndRaw = static_cast<std::size_t>(Page.Raw) + static_cast<std::size_t>(Page.RawSize);
    return Detail::ScanTestThenJz(Bytes, Page.Raw, EndRaw, Page.Rva);
}

inline std::vector<Structs::CiOptionCheck> ScanCiqueryRange(const std::vector<std::uint8_t>& Bytes,
                                                            std::uint32_t StartRva, std::uint32_t EndRva) {
    if (EndRva <= StartRva) {
        return {};
    }
    std::uint32_t StartRaw = 0;
    if (!Pe::RvaToFileOffset(Bytes, StartRva, StartRaw)) {
        return {};
    }
    const std::size_t Len = static_cast<std::size_t>(EndRva - StartRva);
    const std::size_t EndRaw = static_cast<std::size_t>(StartRaw) + Len;
    return Detail::ScanTestThenJz(Bytes, StartRaw, EndRaw, StartRva);
}

} // namespace Decoder
