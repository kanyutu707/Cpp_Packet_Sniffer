#include "JsonExporter.h"
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

JsonExporter::JsonExporter(const std::string& filename) : outFile(filename) {}

void JsonExporter::exportPacket(const PacketInfo& info) {
    json j;
    j["src_ip"] = info.src_ip;
    j["dst_ip"] = info.dst_ip;
    j["src_port"] = info.src_port;
    j["dst_port"] = info.dst_port;
    j["size"] = info.size;
    j["protocol"] = info.protocol;
    if (!info.http_data.empty()) {
        j["http"] = info.http_data;
    }

    std::ofstream ofs(outFile, std::ios::app);
    ofs << j.dump() << std::endl;
}
