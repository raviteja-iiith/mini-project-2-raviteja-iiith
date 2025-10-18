#include "cshark.h"
#include "parser.h"

const char* get_packet_protocol(const unsigned char *packet, int length) {
    if (length < 14) return "Unknown";
    
    struct ether_header *eth = (struct ether_header *)packet;
    unsigned short eth_type = ntohs(eth->ether_type);
    
    if (eth_type == ETHERTYPE_ARP) {
        return "ARP";
    }
    else if (eth_type == ETHERTYPE_IP) {
        if (length < 34) return "IPv4";
        struct ip *iph = (struct ip *)(packet + 14);
        
        switch (iph->ip_p) {
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMP: return "ICMP";
            default: return "IPv4";
        }
    }
    else if (eth_type == ETHERTYPE_IPV6) {
        if (length < 54) return "IPv6";
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + 14);
        
        switch (ip6h->ip6_nxt) {
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMPV6: return "ICMPv6";
            default: return "IPv6";
        }
    }
    
    return "Unknown";
}

void get_packet_addresses(const unsigned char *packet, int length, char *src, char *dst) {
    strcpy(src, "N/A");
    strcpy(dst, "N/A");
    
    if (length < 14) return;
    
    struct ether_header *eth = (struct ether_header *)packet;
    unsigned short eth_type = ntohs(eth->ether_type);
    
    if (eth_type == ETHERTYPE_IP && length >= 34) {
        struct ip *iph = (struct ip *)(packet + 14);
        inet_ntop(AF_INET, &(iph->ip_src), src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dst, INET_ADDRSTRLEN);
    }
    else if (eth_type == ETHERTYPE_IPV6 && length >= 54) {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + 14);
        inet_ntop(AF_INET6, &(ip6h->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, INET6_ADDRSTRLEN);
    }
    else if (eth_type == ETHERTYPE_ARP && length >= 42) {
        unsigned char *arp_data = (unsigned char *)(packet + 14 + 8);
        unsigned char *sender_ip = arp_data;
        unsigned char *target_ip = arp_data + 10;
        sprintf(src, "%d.%d.%d.%d", sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
        sprintf(dst, "%d.%d.%d.%d", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    }
}

void inspect_last_session(void) {
    if (packet_count == 0) {
        printf("\n[C-Shark] No packets in last session. Run a capture first!\n");
        return;
    }
    
    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                              Last Session Packet Summary                                        ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Total packets captured: %d\n\n", packet_count);
    
    int packets_per_page = 50;
    int current_page = 0;
    int total_pages = (packet_count + packets_per_page - 1) / packets_per_page;
    char choice[10];
    
    while (1) {
        
        printf("\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
        printf("Page %d of %d (Showing packets %d-%d of %d total)\n", 
               current_page + 1, total_pages,
               current_page * packets_per_page + 1,
               (current_page + 1) * packets_per_page > packet_count ? packet_count : (current_page + 1) * packets_per_page,
               packet_count);
        printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n\n");
        
        printf("%-8s %-22s %-10s %-10s %-40s %-40s\n", 
               "Packet", "Timestamp", "Length", "Protocol", "Source", "Destination");
        printf("%-8s %-22s %-10s %-10s %-40s %-40s\n", 
               "------", "---------", "------", "--------", "------", "-----------");
        
        int start = current_page * packets_per_page;
        int end = start + packets_per_page;
        if (end > packet_count) end = packet_count;
        
        for (int i = start; i < end; i++) {
            const char *protocol = get_packet_protocol(packet_store[i].data, packet_store[i].length);
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            get_packet_addresses(packet_store[i].data, packet_store[i].length, src, dst);
            
            printf("#%-7d %ld.%06ld   %-10d %-10s %-40s %-40s\n",
                   packet_store[i].id,
                   (long)packet_store[i].timestamp.tv_sec,
                   (long)packet_store[i].timestamp.tv_usec,
                   packet_store[i].length,
                   protocol,
                   src,
                   dst);
        }
        
        printf("\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
        printf("Commands: [N]ext page | [P]revious page | [A]ll packets | [I]nspect packet | [Q]uit\n");
        printf("Enter command: ");
        
        if (scanf("%s", choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');
        
        if (choice[0] == 'n' || choice[0] == 'N') {
            if (current_page < total_pages - 1) {
                current_page++;
            } else {
                printf("Already at last page!\n");
                sleep(1);
            }
        }
        else if (choice[0] == 'p' || choice[0] == 'P') {
            if (current_page > 0) {
                current_page--;
            } else {
                printf("Already at first page!\n");
                sleep(1);
            }
        }
        else if (choice[0] == 'a' || choice[0] == 'A') {
            printf("\n═══════════════════════════════════════════════════════════════════════════════════════════════════\n");
            printf("Displaying ALL %d packets:\n", packet_count);
            printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n\n");
            
            printf("%-8s %-22s %-10s %-10s %-40s %-40s\n", 
                   "Packet", "Timestamp", "Length", "Protocol", "Source", "Destination");
            printf("%-8s %-22s %-10s %-10s %-40s %-40s\n", 
                   "------", "---------", "------", "--------", "------", "-----------");
            
            for (int i = 0; i < packet_count; i++) {
                const char *protocol = get_packet_protocol(packet_store[i].data, packet_store[i].length);
                char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
                get_packet_addresses(packet_store[i].data, packet_store[i].length, src, dst);
                
                printf("#%-7d %ld.%06ld   %-10d %-10s %-40s %-40s\n",
                       packet_store[i].id,
                       (long)packet_store[i].timestamp.tv_sec,
                       (long)packet_store[i].timestamp.tv_usec,
                       packet_store[i].length,
                       protocol,
                       src,
                       dst);
            }
            
            printf("\n[C-Shark] Press Enter to continue...");
            getchar();
        }
        else if (choice[0] == 'i' || choice[0] == 'I') {
            printf("Enter Packet ID to inspect in detail: ");
            int packet_id;
            if (scanf("%d", &packet_id) != 1) {
                while (getchar() != '\n');
                continue;
            }
            while (getchar() != '\n');
            
            int found = -1;
            for (int i = 0; i < packet_count; i++) {
                if (packet_store[i].id == packet_id) {
                    found = i;
                    break;
                }
            }
            
            if (found == -1) {
                printf("[C-Shark] Packet #%d not found in session!\n", packet_id);
                sleep(2);
                continue;
            }
            
            printf("\n");
            printf("╔═══════════════════════════════════════════════════════════════╗\n");
            printf("║              DETAILED PACKET INSPECTION                      ║\n");
            printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
            
            printf("Packet ID: #%d\n", packet_store[found].id);
            printf("Timestamp: %ld.%06ld\n", 
                   (long)packet_store[found].timestamp.tv_sec,
                   (long)packet_store[found].timestamp.tv_usec);
            printf("Length: %d bytes\n", packet_store[found].length);
            printf("Protocol: %s\n\n", get_packet_protocol(packet_store[found].data, packet_store[found].length));
            
            struct pcap_pkthdr header;
            header.ts = packet_store[found].timestamp;
            header.len = packet_store[found].length;
            header.caplen = packet_store[found].length;
            
            printf("═══════════════════ Layer-by-Layer Analysis ═══════════════════\n\n");
            process_packet(&header, packet_store[found].data);
            
            print_hex_dump(packet_store[found].data, packet_store[found].length);
            
            printf("\n[C-Shark] Press Enter to continue...");
            getchar();
        }
        else if (choice[0] == 'q' || choice[0] == 'Q') {
            break;
        }
        else {
            printf("Invalid command!\n");
            sleep(1);
        }
    }
}