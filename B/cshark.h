#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

// Network headers
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

// Configuration
#define MAX_PACKETS 10000
#define PAYLOAD_DISPLAY_SIZE 64

// Packet storage structure
typedef struct {
    int id;
    struct timeval timestamp;
    int length;
    unsigned char *data;
} StoredPacket;

// Global variables
extern pcap_t *handle;
extern StoredPacket *packet_store;
extern int packet_count;
extern int current_packet_id;
extern volatile sig_atomic_t stop_capture;

// Function declarations
void display_banner(void);
int select_interface(char *interface);
void display_main_menu(const char *interface);
void start_sniffing_all(const char *interface);
void start_sniffing_filtered(const char *interface);
void inspect_last_session(void);
void signal_handler(int signum);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet);
void store_packet(const struct pcap_pkthdr *header, const unsigned char *packet);
void free_packet_store(void);

#endif // CSHARK_H