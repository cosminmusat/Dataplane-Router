#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    FILE *fp = fopen("arp_table.txt", "r");
    char line[256];
    unsigned int count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        count++;
    }
    fclose(fp);
    printf("%d\n", count);
}