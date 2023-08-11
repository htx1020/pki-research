#pragma once
#include <stdint.h>
#include <vector>

/* #include <vector> */

namespace pem {

std::vector<uint8_t> ReadPrikey(const char *file);

void WritePrikey(const char *file, const std::vector<uint8_t> &key);

} // namespace pem
