#include "cshark.h"
#include "parser.h"

// Global variables
pcap_t *handle = NULL;
StoredPacket *packet_store = NULL;
int packet_count = 0;
int current_packet_id = 0;
volatile sig_atomic_t stop_capture = 0;

int main() {
    char interface[256];
    int choice;
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    
    display_banner();
    
    // Select interface
    if (select_interface(interface) != 0) {
        fprintf(stderr, "Failed to select interface\n");
        return 1;
    }
    
    // Main menu loop
    while (1) {
        display_main_menu(interface);
        
        if (scanf("%d", &choice) != 1) {
            // Handle Ctrl+D
            printf("\n[C-Shark] Exiting... Goodbye!\n");
            free_packet_store();
            return 0;
        }
        
        // Clear input buffer
        while (getchar() != '\n');
        
        switch (choice) {
            case 1:
                start_sniffing_all(interface);
                break;
            case 2:
                start_sniffing_filtered(interface);
                break;
            case 3:
                inspect_last_session();
                break;
            case 4:
                printf("[C-Shark] Exiting... Goodbye!\n");
                free_packet_store();
                return 0;
            default:
                printf("[C-Shark] Invalid choice. Please try again.\n");
        }
    }
    
    return 0;
}

void display_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║     [C-Shark] The Command-Line Packet Predator       ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

int select_interface(char *interface) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, choice;
    
    printf("[C-Shark] Searching for available interfaces... ");
    
    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    printf("Found!\n\n");
    
    // Print all devices
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    if (i == 0) {
        fprintf(stderr, "No interfaces found!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nSelect an interface to sniff (1-%d): ", i);
    scanf("%d", &choice);
    while (getchar() != '\n');
    
    if (choice < 1 || choice > i) {
        fprintf(stderr, "Invalid choice!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Get selected interface
    d = alldevs;
    for (i = 1; i < choice; i++) {
        d = d->next;
    }
    
    strcpy(interface, d->name);
    pcap_freealldevs(alldevs);
    
    return 0;
}

void display_main_menu(const char *interface) {
    printf("\n");
    printf("══════════════════════════════════════════════════════════\n");
    printf("[C-Shark] Interface '%s' selected. What's next?\n", interface);
    printf("══════════════════════════════════════════════════════════\n\n");
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n\n");
    printf("Enter your choice: ");
}

void signal_handler(int signum) {
    if (signum == SIGINT) {
        stop_capture = 1;
        if (handle != NULL) {
            pcap_breakloop(handle);
        }
    }
}

void start_sniffing_all(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("\n[C-Shark] Starting packet capture on %s...\n", interface);
    printf("[C-Shark] Press Ctrl+C to stop capture\n\n");
    
    // Free previous session
    free_packet_store();
    current_packet_id = 0;
    stop_capture = 0;
    
    // Open device
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return;
    }
    
    // Start capture
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Close handle
    pcap_close(handle);
    handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. %d packets captured.\n", packet_count);
}

void start_sniffing_filtered(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[256] = "";
    int filter_choice;
    
    printf("\n[C-Shark] Select filter:\n");
    printf("1. HTTP\n");
    printf("2. HTTPS\n");
    printf("3. DNS\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf("Enter choice: ");
    
    scanf("%d", &filter_choice);
    while (getchar() != '\n');
    
    switch (filter_choice) {
        case 1:
            strcpy(filter_exp, "tcp port 80");
            break;
        case 2:
            strcpy(filter_exp, "tcp port 443");
            break;
        case 3:
            strcpy(filter_exp, "udp port 53");
            break;
        case 4:
            strcpy(filter_exp, "arp");
            break;
        case 5:
            strcpy(filter_exp, "tcp");
            break;
        case 6:
            strcpy(filter_exp, "udp");
            break;
        default:
            printf("Invalid choice!\n");
            return;
    }
    
    printf("\n[C-Shark] Starting filtered capture on %s with filter: %s\n", interface, filter_exp);
    printf("[C-Shark] Press Ctrl+C to stop capture\n\n");
    
    // Free previous session
    free_packet_store();
    current_packet_id = 0;
    stop_capture = 0;
    
    // Open device
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return;
    }
    
    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    
    pcap_freecode(&fp);
    
    // Start capture
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Close handle
    pcap_close(handle);
    handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. %d packets captured.\n", packet_count);
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    current_packet_id++;
    
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           current_packet_id, (long)header->ts.tv_sec, (long)header->ts.tv_usec, header->len);
    
    process_packet(header, packet);
    store_packet(header, packet);
}

void store_packet(const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (packet_count >= MAX_PACKETS) {
        return; // Max capacity reached
    }
    
    // Allocate memory for packet store if needed
    if (packet_store == NULL) {
        packet_store = (StoredPacket *)malloc(MAX_PACKETS * sizeof(StoredPacket));
        if (packet_store == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
    }
    
    // Store packet
    packet_store[packet_count].id = current_packet_id;
    packet_store[packet_count].timestamp = header->ts;
    packet_store[packet_count].length = header->len;
    packet_store[packet_count].data = (unsigned char *)malloc(header->len);
    
    if (packet_store[packet_count].data == NULL) {
        fprintf(stderr, "Memory allocation failed for packet data\n");
        return;
    }
    
    memcpy(packet_store[packet_count].data, packet, header->len);
    packet_count++;
}

void free_packet_store(void) {
    if (packet_store != NULL) {
        for (int i = 0; i < packet_count; i++) {
            free(packet_store[i].data);
        }
        free(packet_store);
        packet_store = NULL;
    }
    packet_count = 0;
}