#pragma once

#include <cstdint>

namespace Structs {

struct CiOptionCheck {
    std::uint64_t Rva{};
    std::uint64_t FileOffset{};
    std::uint32_t Mask{};
    std::uint8_t JccOpcode{};
};

struct SectionInfo {
    std::uint32_t Rva{};
    std::uint32_t Raw{};
    std::uint32_t RawSize{};
    char Name[9]{};
};

} // namespace Structs
