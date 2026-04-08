#pragma once

#include <cctype>
#include <cstddef>
#include <string>

namespace Pattern {

// Parses a space separated hex pattern with ?? or ? wildcards into bytes + mask ('x' = fixed, '?' = any)
inline bool ParseWildcardText(const std::string& Text, std::string& OutBytes, std::string& OutMask) {
    OutBytes.clear();
    OutMask.clear();
    std::size_t I = 0;

    auto HexNibble = [](char C) -> int {
        if (C >= '0' && C <= '9') return C - '0';
        if (C >= 'a' && C <= 'f') return 10 + (C - 'a');
        if (C >= 'A' && C <= 'F') return 10 + (C - 'A');
        return -1;
    };

    while (I < Text.size()) {
        while (I < Text.size() && std::isspace(static_cast<unsigned char>(Text[I]))) {
            ++I;
        }
        if (I >= Text.size()) {
            break;
        }

        if (Text[I] == '?') {
            ++I;
            if (I < Text.size() && Text[I] == '?') {
                ++I;
            }
            OutBytes.push_back(0);
            OutMask.push_back('?');
            while (I < Text.size() && std::isspace(static_cast<unsigned char>(Text[I]))) {
                ++I;
            }
            continue;
        }

        if (I + 1 >= Text.size()) {
            return false;
        }
        const int Hi = HexNibble(Text[I]);
        const int Lo = HexNibble(Text[I + 1]);
        if (Hi < 0 || Lo < 0) {
            return false;
        }
        OutBytes.push_back(static_cast<char>((Hi << 4) | Lo));
        OutMask.push_back('x');
        I += 2;
        while (I < Text.size() && std::isspace(static_cast<unsigned char>(Text[I]))) {
            ++I;
        }
    }

    return !OutMask.empty();
}

} // namespace Pattern
