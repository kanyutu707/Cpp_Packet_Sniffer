#include "PacketSniffer.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>

PacketSniffer::PacketSniffer(const std::string& interface, const std::string& filter)
    : interface(interface), filter(filter), handle(nullptr) {}

PacketSniffer::~PacketSniffer() {
    stopCapture();
}

bool PacketSniffer::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return false;
    }

    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }

    // Start capturing packets, pass 'this' pointer as user data
    if (pcap_loop(handle, 0, pcapCallback, reinterpret_cast<u_char*>(this)) == -1) {
        std::cerr << "Error during packet capture: " << pcap_geterr(handle) << std::endl;
        return false;
    }

    return true;
}

void PacketSniffer::stopCapture() {
    if (handle) {
        pcap_breakloop(handle);
        pcap_freecode(&fp);
        pcap_close(handle);
        handle = nullptr;
    }
}

// Static callback called by libpcap for every captured packet
void PacketSniffer::pcapCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* sniffer = reinterpret_cast<PacketSniffer*>(args);

    // Parse Ethernet header (assuming Ethernet)
    // Skip Ethernet header (usually 14 bytes)
    const int ethernet_header_length = 14;

    if (header->caplen < ethernet_header_length) {
        // Packet too short
        return;
    }

    const u_char* ip_packet = packet + ethernet_header_length;
    int ip_packet_len = header->caplen - ethernet_header_length;

    // Parse IP header
    struct ip* ip_hdr = (struct ip*)ip_packet;
    if (ip_packet_len < sizeof(struct ip)) {
        return;
    }

    PacketInfo info;
    info.src_ip = inet_ntoa(ip_hdr->ip_src);
    info.dst_ip = inet_ntoa(ip_hdr->ip_dst);
    info.protocol = ip_hdr->ip_p;
    info.size = header->len;

    // Ports default to 0 if not TCP or UDP
    info.src_port = 0;
    info.dst_port = 0;

    // TCP or UDP parsing
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp_hdr = (struct tcphdr*)(ip_packet + ip_hdr->ip_hl * 4);
        if (ip_packet_len >= (ip_hdr->ip_hl * 4 + sizeof(struct tcphdr))) {
            info.src_port = ntohs(tcp_hdr->th_sport);
            info.dst_port = ntohs(tcp_hdr->th_dport);

            // Extract HTTP data if any (assuming TCP payload after tcp header)
            int tcp_header_len = tcp_hdr->th_off * 4;
            int http_data_len = ip_packet_len - ip_hdr->ip_hl * 4 - tcp_header_len;
            if (http_data_len > 0) {
                const char* http_data_ptr = (const char*)(ip_packet + ip_hdr->ip_hl * 4 + tcp_header_len);
                info.http_data = std::string(http_data_ptr, http_data_len);
            }
        }
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp_hdr = (struct udphdr*)(ip_packet + ip_hdr->ip_hl * 4);
        if (ip_packet_len >= (ip_hdr->ip_hl * 4 + sizeof(struct udphdr))) {
            info.src_port = ntohs(udp_hdr->uh_sport);
            info.dst_port = ntohs(udp_hdr->uh_dport);
        }
    }

    // Call the user-defined packet handler if set
    if (sniffer->packetHandler) {
        sniffer->packetHandler(info);
    }
}
