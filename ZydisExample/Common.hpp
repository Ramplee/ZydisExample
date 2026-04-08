#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "utils/logging.hpp"
#include "utils/pe.hpp"
#include "utils/Pattern.hpp"
