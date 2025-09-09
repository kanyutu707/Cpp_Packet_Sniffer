#include <iostream>
#include <csignal>
#include "PacketSniffer.h"
#include "JsonExporter.h"

static PacketSniffer* snifferPtr = nullptr;

void signalHandler(int signum) {
    if (snifferPtr) {
        std::cout << "\nStopping capture..." << std::endl;
        snifferPtr->stopCapture();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <output.json> <filter>\n";
        std::cerr << "Example filter: \"tcp or udp or icmp\"\n";
        return 1;
    }

    std::string interface = argv[1];
    std::string outputFile = argv[2];
    std::string filter = argv[3];

    PacketSniffer sniffer(interface, filter);
    JsonExporter exporter(outputFile);

    sniffer.setPacketHandler([&exporter](const PacketInfo& info) {
        std::cout << "Src IP: " << info.src_ip << " | Dst IP: " << info.dst_ip
                  << " | Proto: " << (int)info.protocol << " | Size: " << info.size << std::endl;
        exporter.exportPacket(info);
    });

    snifferPtr = &sniffer;

    signal(SIGINT, signalHandler);

    if (!sniffer.startCapture()) {
        std::cerr << "Failed to start packet capture.\n";
        return 1;
    }

    std::cout << "Capture stopped.\n";
    return 0;
}
