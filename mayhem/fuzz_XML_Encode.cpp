#include <stdint.h>
#include <stdio.h>
#include "OutputHelpers.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    MediaInfoLib::XML_Encode(str);
    return 0;
}
