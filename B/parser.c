#include "parser.h"

void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet) {
    int offset = 0;
    parse_ethernet(packet, &offset);
}

void parse_ethernet(const unsigned char *packet, int *offset) {
    struct ether_header *eth = (struct ether_header *)packet;
    char src_mac[18], dst_mac[18];
    
    format_mac(eth->ether_shost, src_mac);
    format_mac(eth->ether_dhost, dst_mac);
    
    unsigned short eth_type = ntohs(eth->ether_type);
    
    printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s | \n", dst_mac, src_mac);
    
    *offset = sizeof(struct ether_header);
    
    switch (eth_type) {
        case ETHERTYPE_IP:
            printf("EtherType: IPv4 (0x%04X)\n", eth_type);
            parse_ipv4(packet, offset);
            break;
        case ETHERTYPE_IPV6:
            printf("EtherType: IPv6 (0x%04X)\n", eth_type);
            parse_ipv6(packet, offset);
            break;
        case ETHERTYPE_ARP:
            printf("EtherType: ARP (0x%04X)\n", eth_type);
            parse_arp(packet, offset);
            break;
        default:
            printf("EtherType: Unknown (0x%04X)\n", eth_type);
            break;
    }
}

void parse_ipv4(const unsigned char *packet, int *offset) {
    struct ip *iph = (struct ip *)(packet + *offset);
    int ip_header_len = iph->ip_hl * 4;
    
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    const char *protocol_name;
    switch (iph->ip_p) {
        case IPPROTO_TCP:
            protocol_name = "TCP";
            break;
        case IPPROTO_UDP:
            protocol_name = "UDP";
            break;
        case IPPROTO_ICMP:
            protocol_name = "ICMP";
            break;
        default:
            protocol_name = "Unknown";
            break;
    }
    
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
           src_ip, dst_ip, protocol_name, iph->ip_p, iph->ip_ttl);
    printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
           ntohs(iph->ip_id), ntohs(iph->ip_len), ip_header_len);
    
    *offset += ip_header_len;
    
    switch (iph->ip_p) {
        case IPPROTO_TCP:
            parse_tcp(packet, *offset, ip_header_len);
            break;
        case IPPROTO_UDP:
            parse_udp(packet, *offset, ip_header_len);
            break;
    }
}

void parse_ipv6(const unsigned char *packet, int *offset) {
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + *offset);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    
    format_ipv6(&(ip6h->ip6_src), src_ip);
    format_ipv6(&(ip6h->ip6_dst), dst_ip);
    
    const char *next_header_name;
    switch (ip6h->ip6_nxt) {
        case IPPROTO_TCP:
            next_header_name = "TCP";
            break;
        case IPPROTO_UDP:
            next_header_name = "UDP";
            break;
        case IPPROTO_ICMPV6:
            next_header_name = "ICMPv6";
            break;
        default:
            next_header_name = "Unknown";
            break;
    }
    
    unsigned int flow_label = ntohl(ip6h->ip6_flow) & 0x000FFFFF;
    unsigned int traffic_class = (ntohl(ip6h->ip6_flow) >> 20) & 0xFF;
    
    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
    printf("Next Header: %s (%d) | Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           next_header_name, ip6h->ip6_nxt, ip6h->ip6_hlim, traffic_class, flow_label, ntohs(ip6h->ip6_plen));
    
    *offset += sizeof(struct ip6_hdr);
    
    switch (ip6h->ip6_nxt) {
        case IPPROTO_TCP:
            parse_tcp(packet, *offset, 0);
            break;
        case IPPROTO_UDP:
            parse_udp(packet, *offset, 0);
            break;
    }
}

void parse_arp(const unsigned char *packet, int *offset) {
    struct arphdr *arph = (struct arphdr *)(packet + *offset);
    unsigned char *arp_data = (unsigned char *)(packet + *offset + sizeof(struct arphdr));
    
    unsigned short operation = ntohs(arph->ar_op);
    const char *op_name = (operation == ARPOP_REQUEST) ? "Request" : 
                          (operation == ARPOP_REPLY) ? "Reply" : "Unknown";
    
    // Extract sender and target info
    unsigned char *sender_mac = arp_data;
    unsigned char *sender_ip = arp_data + 6;
    unsigned char *target_mac = arp_data + 10;
    unsigned char *target_ip = arp_data + 16;
    
    char sender_mac_str[18], target_mac_str[18];
    format_mac(sender_mac, sender_mac_str);
    format_mac(target_mac, target_mac_str);
    
    printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %d.%d.%d.%d | Target IP: %d.%d.%d.%d\n",
           op_name, operation,
           sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    printf("Sender MAC: %s | Target MAC: %s\n", sender_mac_str, target_mac_str);
    printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
           ntohs(arph->ar_hrd), ntohs(arph->ar_pro), arph->ar_hln, arph->ar_pln);
}

// Add to parser.c - improved parse_tcp function
void parse_tcp(const unsigned char *packet, int offset, int ip_header_len) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + offset);
    int tcp_header_len = tcph->th_off * 4;
    
    int src_port = ntohs(tcph->th_sport);
    int dst_port = ntohs(tcph->th_dport);
    
    const char *src_service = get_port_service(src_port);
    const char *dst_service = get_port_service(dst_port);
    
    printf("L4 (TCP): Src Port: %d", src_port);
    if (strcmp(src_service, "Unknown") != 0)
        printf(" (%s)", src_service);
    printf(" | Dst Port: %d", dst_port);
    if (strcmp(dst_service, "Unknown") != 0)
        printf(" (%s)", dst_service);
    
    printf(" | Seq: %u | Ack: %u | Flags: [",
           ntohl(tcph->th_seq), ntohl(tcph->th_ack));
    
    int flag_count = 0;
    if (tcph->th_flags & TH_FIN) { if (flag_count++) printf(","); printf("FIN"); }
    if (tcph->th_flags & TH_SYN) { if (flag_count++) printf(","); printf("SYN"); }
    if (tcph->th_flags & TH_RST) { if (flag_count++) printf(","); printf("RST"); }
    if (tcph->th_flags & TH_PUSH) { if (flag_count++) printf(","); printf("PSH"); }
    if (tcph->th_flags & TH_ACK) { if (flag_count++) printf(","); printf("ACK"); }
    if (tcph->th_flags & TH_URG) { if (flag_count++) printf(","); printf("URG"); }
    
    printf("]\nWindow: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
           ntohs(tcph->th_win), ntohs(tcph->th_sum), tcp_header_len);
    
    int payload_offset = offset + tcp_header_len;
    
    // Calculate payload length properly
    // We need the IP total length to calculate this
    // For now, we'll pass 0 and handle it in parse_payload
    parse_payload(packet, payload_offset, 0, src_port, dst_port);
}

void parse_udp(const unsigned char *packet, int offset, int ip_header_len) {
    struct udphdr *udph = (struct udphdr *)(packet + offset);
    
    int src_port = ntohs(udph->uh_sport);
    int dst_port = ntohs(udph->uh_dport);
    
    const char *src_service = get_port_service(src_port);
    const char *dst_service = get_port_service(dst_port);
    
    printf("L4 (UDP): Src Port: %d", src_port);
    if (strcmp(src_service, "Unknown") != 0)
        printf(" (%s)", src_service);
    printf(" | Dst Port: %d", dst_port);
    if (strcmp(dst_service, "Unknown") != 0)
        printf(" (%s)", dst_service);
    
    printf(" | Length: %d | Checksum: 0x%04X\n",
           ntohs(udph->uh_ulen), ntohs(udph->uh_sum));
    
    int payload_offset = offset + sizeof(struct udphdr);
    int payload_len = ntohs(udph->uh_ulen) - sizeof(struct udphdr);
    
    parse_payload(packet, payload_offset, payload_len, src_port, dst_port);
}

void parse_payload(const unsigned char *packet, int offset, int payload_len, int src_port, int dst_port) {
    const char *protocol = "Unknown";
    
    if (src_port == 80 || dst_port == 80)
        protocol = "HTTP";
    else if (src_port == 443 || dst_port == 443)
        protocol = "HTTPS/TLS";
    else if (src_port == 53 || dst_port == 53)
        protocol = "DNS";
    
    // Calculate actual payload length if not provided
    if (payload_len <= 0) {
        return; // No payload
    }
    
    printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
           protocol, (src_port == 80 || src_port == 443 || src_port == 53) ? src_port : dst_port,
           payload_len);
    
    int display_len = (payload_len < PAYLOAD_DISPLAY_SIZE) ? payload_len : PAYLOAD_DISPLAY_SIZE;
    printf("Data (first %d bytes):\n", display_len);
    print_hex_ascii_line(packet + offset, display_len, 0);
}

const char* get_port_service(int port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-ALT";
        default: return "Unknown";
    }
}

void print_hex_ascii_line(const unsigned char *payload, int len, int offset) {
    int i;
    const unsigned char *ch = payload;
    
    for (i = 0; i < len; i += 16) {
        // Print hex
        for (int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02X ", ch[i + j]);
            else
                printf("   ");
        }
        
        printf(" ");
        
        // Print ASCII
        for (int j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = ch[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("\n");
    }
}

void print_hex_dump(const unsigned char *data, int length) {
    printf("\n=== Full Packet Hex Dump ===\n");
    print_hex_ascii_line(data, length, 0);
    printf("=== End of Hex Dump ===\n\n");
}

void format_mac(const unsigned char *mac, char *output) {
    sprintf(output, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_ipv6(const struct in6_addr *addr, char *output) {
    inet_ntop(AF_INET6, addr, output, INET6_ADDRSTRLEN);
}