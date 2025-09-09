#pragma once
#include <string>
#include <functional>   
#include <pcap/pcap.h>

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t size;
    uint8_t protocol;
    std::string http_data;
};

class PacketSniffer {
public:
    PacketSniffer(const std::string& interface, const std::string& filter);
    ~PacketSniffer();
    bool startCapture();
    void stopCapture();

    void setPacketHandler(std::function<void(const PacketInfo&)> handler) { packetHandler = handler; }

private:
    std::string interface;
    std::string filter;
    pcap_t* handle = nullptr;
    bpf_program fp{};
    std::function<void(const PacketInfo&)> packetHandler = nullptr;  

    static void pcapCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
};
