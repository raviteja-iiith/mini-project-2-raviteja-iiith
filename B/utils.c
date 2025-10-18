#include "cshark.h"
#include "parser.h"

int get_total_packet_length(const struct pcap_pkthdr *header) {
    return header->len;
}

void display_packet_statistics(void) {
    if (packet_count == 0) {
        printf("No packets captured yet.\n");
        return;
    }
    
    int tcp_count = 0, udp_count = 0, arp_count = 0, other_count = 0;
    
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║      Packet Statistics                ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");
    
    printf("Total Packets: %d\n", packet_count);
    printf("TCP Packets: %d\n", tcp_count);
    printf("UDP Packets: %d\n", udp_count);
    printf("ARP Packets: %d\n", arp_count);
    printf("Other Packets: %d\n", other_count);
}

void export_session_to_file(const char *filename) {
    if (packet_count == 0) {
        printf("No packets to export.\n");
        return;
    }
    
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file for writing.\n");
        return;
    }
    
    fprintf(fp, "C-Shark Packet Capture Export\n");
    fprintf(fp, "==============================\n\n");
    fprintf(fp, "Total Packets: %d\n\n", packet_count);
    
    for (int i = 0; i < packet_count; i++) {
        fprintf(fp, "Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
                packet_store[i].id,
                (long)packet_store[i].timestamp.tv_sec,
                (long)packet_store[i].timestamp.tv_usec,
                packet_store[i].length);
    }
    
    fclose(fp);
    printf("Session exported to %s\n", filename);
}