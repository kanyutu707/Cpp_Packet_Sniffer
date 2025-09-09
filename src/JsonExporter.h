#pragma once
#include <string>
#include "PacketSniffer.h"

class JsonExporter {
public:
    explicit JsonExporter(const std::string& filename);
    void exportPacket(const PacketInfo& info);

private:
    std::string outFile;
};
