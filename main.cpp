#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cctype> 
#include <string> // NEW: Library for searching text

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* handle = pcap_open_offline("sample.pcap", errbuf);

    if (handle == nullptr) {
        std::cout << "ERROR: Could not open file!" << std::endl;
        return 1; 
    }

    std::cout << "--- DPI ENGINE: ACTIVE SCANNING ---" << std::endl;

    struct pcap_pkthdr* header;
    const u_char* packet; 
    int packetCount = 0;

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        packetCount++;
        
        const u_char* ip_payload = packet + 14; 
        struct ip* ip_header = (struct ip*)ip_payload;

        if (ip_header->ip_p == IPPROTO_TCP) {
            
            int ip_header_length = ip_header->ip_hl * 4;
            const u_char* tcp_payload = ip_payload + ip_header_length;
            struct tcphdr* tcp_header = (struct tcphdr*)tcp_payload;
            int tcp_header_length = tcp_header->th_off * 4;
            const u_char* actual_data = tcp_payload + tcp_header_length;
            
            int total_ip_length = ntohs(ip_header->ip_len);
            int payload_length = total_ip_length - (ip_header_length + tcp_header_length);

            if (payload_length > 0) {
                // 1. Convert the raw payload into a searchable text string
                std::string readable_payload = "";
                for (int i = 0; i < payload_length; i++) {
                    if (std::isprint(actual_data[i])) {
                        readable_payload += actual_data[i];
                    } else {
                        readable_payload += ".";
                    }
                }
                
                std::cout << "Packet " << packetCount << " | Payload size: " << payload_length << " bytes." << std::endl;

                // 2. THE DPI FIREWALL RULE
                // Search the string for specific target words
                if (readable_payload.find("com") != std::string::npos || 
                    readable_payload.find("http") != std::string::npos) {
                    
                    std::cout << "  [!!!] THREAT DETECTED: Target keyword found in payload!" << std::endl;
                    std::cout << "  [!!!] ACTION: Dropping Packet..." << std::endl;
                } else {
                    std::cout << "  [OK] Packet clean. Allowed." << std::endl;
                }
                std::cout << "-----------------------------------" << std::endl;
            }
        }
    }

    pcap_close(handle);
    return 0;
}