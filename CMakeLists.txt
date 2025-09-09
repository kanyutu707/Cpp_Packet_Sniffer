cmake_minimum_required(VERSION 3.10)
project(PacketSniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS} ../external/json)
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

add_executable(packet_sniffer
    src/main.cpp
    src/PacketSniffer.cpp
    src/JsonExporter.cpp
)

target_link_libraries(packet_sniffer ${PCAP_LIBRARIES})
