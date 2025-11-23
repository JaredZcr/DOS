#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

volatile sig_atomic_t running = 1;

int THRESHOLD = 1000;
int UPDATE_INTERVAL = 1;

int packet_count = 0;
time_t start_time;
unsigned long total_packets = 0;
unsigned long attack_count = 0;

const char* LOG_FILENAME = "dos_log.txt";

const char* WEB_FILENAME = "dos_status.txt";

void handle_sigint(int signum) {
    (void)signum;
    running = 0;
    printf("\n[System] Stopping capture...\n");
}

void update_web_status(time_t current_time, int count, int alerted) {
    FILE* webfp = fopen(WEB_FILENAME, "w");
    if (webfp) {

        fprintf(webfp, "%lld,%d,%d", (long long)current_time, count, alerted ? 1 : 0);
        fclose(webfp);
    }
}

void load_config(const char* cfgfile) {
    FILE* f = fopen(cfgfile, "r");
    if (!f) {
        printf("[Config] No config file found, using defaults (Threshold=%d).\n", THRESHOLD);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[128];
        int value;
        if (sscanf(line, "%127[^=]=%d", key, &value) == 2) {
            if (strcmp(key, "threshold") == 0) THRESHOLD = value;
            else if (strcmp(key, "update_interval") == 0) UPDATE_INTERVAL = value;
        }
    }
    fclose(f);
    printf("[Config] Loaded: threshold=%d, interval=%d\n", THRESHOLD, UPDATE_INTERVAL);
}

void log_result(time_t t, int pkt_count, int alerted) {
    FILE* fp = fopen(LOG_FILENAME, "a");
    if (!fp) return;
    char buf[64];
    struct tm tm;
    localtime_s(&tm, &t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(fp, "[%s] Packets: %-6d Status: %s\n", buf, pkt_count, alerted ? "ATTACK" : "NORMAL");
    fclose(fp);
}

void detect_dos(pcap_t* handle) {
    packet_count = 0;
    start_time = time(NULL);

    printf("\n[System] Monitoring started.\n");
    printf("[Output] Web status file: ./%s (Open index.html to view)\n", WEB_FILENAME);

    struct pcap_pkthdr* headerPtr = NULL;
    const u_char* packet = NULL;

    update_web_status(start_time, 0, 0);

    while (running) {

        int res = pcap_next_ex(handle, &headerPtr, &packet);

        if (res == 1) {
            packet_count++;
            total_packets++;
        }
        else if (res == -1) {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        }

        time_t current_time = time(NULL);

        if (difftime(current_time, start_time) >= UPDATE_INTERVAL) {
            int alerted = (packet_count > THRESHOLD);

            if (alerted) {
                printf("\r[%lld] 🚨 ALERT: DoS Detected! PPS: %d      ", (long long)current_time, packet_count);
                attack_count++;
                fflush(stdout);
            }
            else if (packet_count > 0) {
                printf("\r[%lld] ✅ Normal traffic. PPS: %d      ", (long long)current_time, packet_count);
                fflush(stdout);
            }
            else {

            }

            log_result(current_time, packet_count, alerted);
            update_web_status(current_time, packet_count, alerted);

            packet_count = 0;
            start_time = current_time;
        }
    }

    printf("\n\n--- Statistics ---\n");
    printf("Total Packets: %lu\n", total_packets);
    printf("Alert Events:  %lu\n", attack_count);
}

const char* select_device(pcap_if_t* alldevs) {
    int i = 0;
    pcap_if_t* d;
    printf("Available network devices:\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description)
            printf("   Description: %s\n", d->description);
    }

    if (i == 0) return NULL;

    char buf[32];
    while (1) {
        printf("\nSelect interface (1-%d): ", i);
        if (!fgets(buf, sizeof(buf), stdin)) return NULL;
        int choice = atoi(buf);
        if (choice >= 1 && choice <= i) {
            int idx = 1;
            for (d = alldevs; d; d = d->next, idx++) {
                if (idx == choice) return d->name;
            }
        }
        printf("Invalid choice.\n");
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handle_sigint);

    printf("========================================\n");
    printf("   DoS Traffic Monitor (Backend) \n");
    printf("========================================\n");

    const char* cfgfile = "config.txt";
    if (argc >= 2) cfgfile = argv[1];
    load_config(cfgfile);

 
    printf("[Init] Creating initial status file...\n");
    update_web_status(time(NULL), 0, 0);

    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    const char* device_name = select_device(alldevs);
    if (device_name == NULL) {
        pcap_freealldevs(alldevs);
        return 0;
    }

    handle = pcap_open_live(device_name, 65536, 1, 500, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "\nError opening device. Make sure you are running as ADMIN.\n%s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);

    detect_dos(handle);
    pcap_close(handle);

    return 0;
}