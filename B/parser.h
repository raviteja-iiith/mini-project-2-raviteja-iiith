#ifndef PARSER_H
#define PARSER_H

#include "cshark.h"

// Parser functions
void parse_ethernet(const unsigned char *packet, int *offset);
void parse_ipv4(const unsigned char *packet, int *offset);
void parse_ipv6(const unsigned char *packet, int *offset);
void parse_arp(const unsigned char *packet, int *offset);
void parse_tcp(const unsigned char *packet, int offset, int ip_header_len);
void parse_udp(const unsigned char *packet, int offset, int ip_header_len);
void parse_payload(const unsigned char *packet, int offset, int payload_len, int src_port, int dst_port);

// Utility functions
const char* get_port_service(int port);
void print_hex_ascii_line(const unsigned char *payload, int len, int offset);
void print_hex_dump(const unsigned char *data, int length);
void format_mac(const unsigned char *mac, char *output);
void format_ipv6(const struct in6_addr *addr, char *output);
// Add these declarations
const char* get_packet_protocol(const unsigned char *packet, int length);
void get_packet_addresses(const unsigned char *packet, int length, char *src, char *dst);
#endif // PARSER_H