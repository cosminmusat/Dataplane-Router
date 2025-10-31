#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

uint16_t IP = 0x0800;

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *mac_table;
int mac_table_len;

typedef struct unit tree;

struct unit{
	tree * left;
	tree * right;
	struct route_table_entry *entry;
};

tree* createNode() {
	tree* t = malloc(sizeof(tree));
	t->left = NULL;
	t->right = NULL;
	t->entry = NULL;
	return t;
}

void add_to_tree(tree* t, uint32_t ip, uint32_t mask, struct route_table_entry* entry) {
	for (int i = 31; i >= 0; i--) {
		if ((ip >> i) % 2 == 1) {
			if (t->right == NULL) {
				tree * st = createNode();
				t->right = st;
				t = t->right;
			}
			else {
				t = t->right;
			}
		}
		else {
			if (t->left == NULL) {
				tree * st = createNode();
				t->left = st;
				t = t->left;
			}
			else {
				t = t->left;
			}
		}
		if (!(mask << (32 - i))) {
			t->entry = entry;
			break;
		}
	}
}

struct route_table_entry* get_best_route(tree* t, uint32_t ip) {
	ip = ntohl(ip);
	struct route_table_entry* best_route = NULL;
	for (int i = 31; i >= 0; i--) {
		if (t == NULL) {
			break;
		}
		else {
			best_route = t->entry;
		}
		if ((ip >> i) % 2 == 1) {
			t = t->right;
		}
		else {
			t = t->left;
		}
	}
	return best_route;
}

void create_tree(tree* t) {
	for (int i = 0; i < rtable_len; i++) {
		add_to_tree(t, ntohl(rtable[i].prefix), ntohl(rtable[i].mask), NULL);
	}
	for (int i = 0; i < rtable_len; i++) {
		add_to_tree(t, ntohl(rtable[i].prefix), ntohl(rtable[i].mask), &rtable[i]);
	}
}


struct arp_entry *get_mac_entry(uint32_t ip) {
	for (int i = 0; i < mac_table_len; i++) {
		if (ip == mac_table[i].ip) {
			return &mac_table[i];
		}
	}
	return NULL;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = (struct route_table_entry *)malloc(100000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);
	mac_table = (struct arp_entry *)malloc(100000 * sizeof(struct arp_entry));
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	tree* origin = createNode();
	create_tree(origin);
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint8_t *mac = malloc(6);

		char *ip = get_interface_ip(interface);
		uint32_t _ip;
		inet_pton(AF_INET, ip, &_ip);

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		size_t buf_icmp_len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

		char* buf_icmp = (char *)malloc(buf_icmp_len);
		struct ether_header* icmp_eth = (struct ether_header *)buf_icmp;
		struct iphdr* icmp_ip = (struct iphdr *)(buf_icmp + sizeof(struct ether_header));
		struct icmphdr* icmp = (struct icmphdr *)(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr));
		memcpy(buf_icmp + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));
		memcpy(buf_icmp + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

		icmp_eth->ether_type = htons(IP);

		icmp_ip->ihl = 5;
		icmp_ip->version = 4;
		icmp_ip->tos = 0;
		icmp_ip->tot_len = htons((uint16_t)(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8));
		icmp_ip->frag_off = 0;
		icmp_ip->ttl = 64;
		icmp_ip->id = htons(1);
		icmp_ip->protocol = IPPROTO_ICMP;
		icmp_ip->daddr = ip_hdr->saddr;
		icmp_ip->saddr = _ip;
		icmp_ip->check = 0;
		icmp_ip->check = htons(checksum((uint16_t *)icmp_ip, sizeof(struct iphdr)));
		icmp->code = 0;

		if(ip_hdr->daddr == _ip) {
			struct ether_header* aux_icmp_eth = (struct ether_header *)buf;
			struct iphdr* aux_icmp_ip = (struct iphdr *)(buf + sizeof(struct ether_header));
			struct icmphdr* aux_icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (aux_icmp->type != 8) {
				continue;
			}
			aux_icmp_ip->daddr = aux_icmp_ip->saddr;
			aux_icmp_ip->saddr = _ip;
			aux_icmp_ip->ttl = 64;
			aux_icmp_ip->check = 0;
			aux_icmp_ip->check = htons(checksum((uint16_t *)aux_icmp_ip, sizeof(struct iphdr)));
			aux_icmp->type = 0;
			aux_icmp->checksum = htons(checksum((uint16_t *)aux_icmp, sizeof(struct icmphdr)));
			struct route_table_entry *best = get_best_route(origin, aux_icmp_ip->daddr);
			get_interface_mac(best->interface, mac);
			memcpy(aux_icmp_eth->ether_shost, mac, 6);
			struct arp_entry *d = get_mac_entry(best->next_hop);
			memcpy(aux_icmp_eth->ether_dhost, d->mac, 6);
			send_to_link(best->interface, buf, len);
			continue;
		}

		uint16_t cs = ntohs(ip_hdr->check);
		ip_hdr->check = 0;

		if(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != cs) {
			continue;
		}

		if(ip_hdr->ttl <= 1) {
			icmp->type = 11;
			icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(struct icmphdr)));
			struct route_table_entry *best = get_best_route(origin, icmp_ip->daddr);
			get_interface_mac(best->interface, mac);
			memcpy(icmp_eth->ether_shost, mac, 6);
			struct arp_entry *d = get_mac_entry(best->next_hop);
			memcpy(icmp_eth->ether_dhost, d->mac, 6);
			send_to_link(best->interface, buf_icmp, buf_icmp_len);
			continue;
		}

		ip_hdr->ttl = ip_hdr->ttl - 1;

		struct route_table_entry *best_route = get_best_route(origin, ip_hdr->daddr);

		if (best_route == NULL) {
			icmp->type = 3;
			icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(struct icmphdr)));
			struct route_table_entry *best = get_best_route(origin, icmp_ip->daddr);
			get_interface_mac(best->interface, mac);
			memcpy(icmp_eth->ether_shost, mac, 6);
			struct arp_entry *d = get_mac_entry(best->next_hop);
			memcpy(icmp_eth->ether_dhost, d->mac, 6);
			send_to_link(best->interface, buf_icmp, buf_icmp_len);
			continue;
		}

		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


		struct arp_entry *dest = get_mac_entry(best_route->next_hop);

		if (dest == NULL) {
			continue;
		}

		get_interface_mac(best_route->interface, mac);

		memcpy(eth_hdr->ether_dhost, dest->mac, 6);
		memcpy(eth_hdr->ether_shost, mac, 6);

		send_to_link(best_route->interface, buf, len);
	}
}
