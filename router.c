#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <inttypes.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST_OPCODE 1
#define ARP_REPLY_OPCODE 2
#define ICMP_TYPE_DEST_UNRC 3
#define ICMP_TYPE_TIME_EXCD 1
#define IP_PROTO_ICMP 1

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// both rt and arp table are in network byte order
	// do not network order rentry->interface!

	unsigned int rt_no_entries = count_lines(argv[1]);
	struct route_table_entry *rt = malloc(rt_no_entries * sizeof(struct route_table_entry));
	read_rtable(argv[1], rt);

	unsigned int at_no_entries = count_lines("arp_table.txt");
	unsigned int at_capacity = at_no_entries;
	struct arp_table_entry *at = malloc(at_capacity * sizeof(struct arp_table_entry));
	parse_arp_table("arp_table.txt", at);

	queue awaiting_arp_reply_pckts = create_queue();
	queue awaiting_arp_reply_pckt_szs = create_queue();

	// fprintf(stderr, "prefix: 0x%" PRIx32 ", next_hop: 0x%" PRIx32 ", mask: 0x%" PRIx32 "\n", rt[9136].prefix, rt[9136].next_hop, rt[9136].mask);
	// fprintf(stderr, "prefix: 0x%" PRIx32 ", next_hop: 0x%" PRIx32 ", mask: 0x%" PRIx32 "\n", rt[51469].prefix, rt[51469].next_hop, rt[51469].mask);
	// fprintf(stderr, "ip: 0x%" PRIx32 "\n", at[0].ip);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eh = (struct ether_hdr*)buf;
		uint16_t ether_type = ntohs(eh->ethr_type);

		uint8_t int_mac[6];
		get_interface_mac(interface, int_mac);

		int broadcast = 1;
		int is_router_dest = 1;
		for (int i = 0; i < 6; ++i) {
			if (eh->ethr_dhost[i] != 0xFF) {
				broadcast = 0;
			}
			if (eh->ethr_dhost[i] != int_mac[i]) {
				is_router_dest = 0;
			}
		}

		if (!(broadcast || is_router_dest)) {
			fprintf(stderr, "Packet dropped, not broadcast nor is router destination\n");
			continue;
		}

		if (ether_type == ETHERTYPE_IP) {
			struct ip_hdr *ih = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
			uint32_t int_ip = inet_addr(get_interface_ip(interface));

			if (ih->dest_addr == int_ip) {
				// router is the destination
				size_t echo_reply_len = sizeof(struct ether_hdr) + sizeof (struct ip_hdr) + sizeof(struct icmp_hdr);
				size_t data_len = (len - echo_reply_len);
				echo_reply_len += data_len;
				char *echo_reply = malloc(echo_reply_len);

				struct ether_hdr *echo_reply_eh = (struct ether_hdr*)echo_reply;
				for (int i = 0; i < 6; ++i) {
					echo_reply_eh->ethr_dhost[i] = eh->ethr_shost[i];
					echo_reply_eh->ethr_shost[i] = eh->ethr_dhost[i];
				}
				echo_reply_eh->ethr_type = htons(ETHERTYPE_IP);

				struct ip_hdr *echo_reply_ih = (struct ip_hdr*)(echo_reply + sizeof(struct ether_hdr));
				echo_reply_ih->dest_addr = ih->source_addr;
				echo_reply_ih->source_addr = ih->dest_addr;
				echo_reply_ih->proto = IP_PROTO_ICMP;
				echo_reply_ih->tos = 0;
				echo_reply_ih->frag = 0;
				echo_reply_ih->ver = 4;
				echo_reply_ih->ihl = 5;
				echo_reply_ih->id = htons(4);
				echo_reply_ih->ttl = 64;
				uint16_t tot_len = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + data_len;
				echo_reply_ih->tot_len = htons(tot_len);
				echo_reply_ih->checksum = 0;
				uint16_t checksum_ip = checksum((uint16_t*)echo_reply_ih, sizeof(struct ip_hdr));
				echo_reply_ih->checksum = htons(checksum_ip);

				struct icmp_hdr *echo_reply_icmph = (struct icmp_hdr*)(echo_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				echo_reply_icmph->mtype = 0;
				echo_reply_icmph->mcode = 0;

				struct icmp_hdr *echo_request_icmph = (struct icmp_hdr*)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				echo_reply_icmph->un_t.echo_t.id = echo_request_icmph->un_t.echo_t.id;
				echo_reply_icmph->un_t.echo_t.seq = echo_request_icmph->un_t.echo_t.seq;
				echo_reply_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)echo_reply_icmph, sizeof(struct icmp_hdr));
				echo_reply_icmph->check = htons(checksum_icmp);

				memcpy(echo_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), data_len);

				send_to_link(echo_reply_len, echo_reply, interface);
				free(echo_reply);
				continue;
			}

			uint16_t checksum_h = ntohs(ih->checksum);
			ih->checksum = 0;
			uint16_t checksum_recalc = checksum((uint16_t*)ih, sizeof(struct ip_hdr));

			if (checksum_h != checksum_recalc) {
				continue;
			}

			ih->checksum = htons(checksum_h);

			if (ih->ttl <= 1) {
				// send icmp packet "Time exceeded"
				size_t dest_unrc_icmp_len = sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				char *dest_unrc_icmp = malloc(dest_unrc_icmp_len);

				struct ether_hdr *icmp_eh = (struct ether_hdr*)dest_unrc_icmp;
				for (int i = 0; i < 6; ++i) {
					icmp_eh->ethr_dhost[i] = eh->ethr_shost[i];
					icmp_eh->ethr_shost[i] = eh->ethr_dhost[i];
				}
				icmp_eh->ethr_type = htons(ETHERTYPE_IP);

				struct ip_hdr *icmp_ih = (struct ip_hdr*)(dest_unrc_icmp + sizeof(struct ether_hdr));
				icmp_ih->dest_addr = ih->source_addr;
				icmp_ih->source_addr = int_ip;
				icmp_ih->proto = IP_PROTO_ICMP;
				icmp_ih->tos = 0;
				icmp_ih->frag = 0;
				icmp_ih->ver = 4;
				icmp_ih->ihl = 5;
				icmp_ih->id = htons(4);
				icmp_ih->ttl = 64;
				uint16_t tot_len = 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				icmp_ih->tot_len = htons(tot_len);
				icmp_ih->checksum = 0;
				uint16_t checksum_ip = checksum((uint16_t*)icmp_ih, sizeof(struct ip_hdr));
				icmp_ih->checksum = htons(checksum_ip);

				struct icmp_hdr *icmp_icmph = (struct icmp_hdr*)(dest_unrc_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				icmp_icmph->mtype = 11;
				icmp_icmph->mcode = 0;
				icmp_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)icmp_icmph, sizeof(struct icmp_hdr));
				icmp_icmph->check = htons(checksum_icmp);

				memcpy(dest_unrc_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ih, sizeof(struct ip_hdr) + 8);

				send_to_link(dest_unrc_icmp_len, dest_unrc_icmp, interface);
				free(dest_unrc_icmp);
				continue;
			}

			--ih->ttl;


			struct route_table_entry* rt_entry = search_rtable(rt, ih->dest_addr, rt_no_entries);

			if (rt_entry == NULL) {
				// send icmp packet "Destination unreachable"
				size_t dest_unrc_icmp_len = sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				char *dest_unrc_icmp = malloc(dest_unrc_icmp_len);

				struct ether_hdr *icmp_eh = (struct ether_hdr*)dest_unrc_icmp;
				for (int i = 0; i < 6; ++i) {
					icmp_eh->ethr_dhost[i] = eh->ethr_shost[i];
					icmp_eh->ethr_shost[i] = eh->ethr_dhost[i];
				}
				icmp_eh->ethr_type = htons(ETHERTYPE_IP);

				struct ip_hdr *icmp_ih = (struct ip_hdr*)(dest_unrc_icmp + sizeof(struct ether_hdr));
				icmp_ih->dest_addr = ih->source_addr;
				icmp_ih->source_addr = int_ip;
				icmp_ih->proto = IP_PROTO_ICMP;
				icmp_ih->tos = 0;
				icmp_ih->frag = 0;
				icmp_ih->ver = 4;
				icmp_ih->ihl = 5;
				icmp_ih->id = htons(4);
				icmp_ih->ttl = 64;
				uint16_t tot_len = 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				icmp_ih->tot_len = htons(tot_len);
				icmp_ih->checksum = 0;
				uint16_t checksum_ip = checksum((uint16_t*)icmp_ih, sizeof(struct ip_hdr));
				icmp_ih->checksum = htons(checksum_ip);

				struct icmp_hdr *icmp_icmph = (struct icmp_hdr*)(dest_unrc_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				icmp_icmph->mtype = 3;
				icmp_icmph->mcode = 0;
				icmp_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)icmp_icmph, sizeof(struct icmp_hdr));
				icmp_icmph->check = htons(checksum_icmp);

				memcpy(dest_unrc_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ih, sizeof(struct ip_hdr) + 8);

				send_to_link(dest_unrc_icmp_len, dest_unrc_icmp, interface);
				free(dest_unrc_icmp);

				continue;
			}
			
			ih->checksum = 0;
			uint16_t checksum_ttl = checksum((uint16_t*)ih, sizeof(struct ip_hdr));
			ih->checksum = htons(checksum_ttl);

			// rewrite L2 addresses using arp
			struct arp_table_entry *at_entry = search_arp_table(at, rt_entry->next_hop, at_no_entries);
			
			if (at_entry == NULL) {
				char *packet = malloc(MAX_PACKET_LEN);
				memcpy(packet, buf, len);
				size_t* len_ptr = malloc(sizeof(size_t));
				*len_ptr = len;
				queue_enq(awaiting_arp_reply_pckts, packet);
				queue_enq(awaiting_arp_reply_pckt_szs, len_ptr);

				// send query arp packet
				size_t arp_req_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
				char *arp_request = malloc(arp_req_len);
				struct ether_hdr *eh = (struct ether_hdr*)arp_request;
				eh->ethr_type = htons(ETHERTYPE_ARP);

				uint8_t interface_mac_to_next_hop[6];
				get_interface_mac(rt_entry->interface, interface_mac_to_next_hop);

				for (int i = 0; i < 6; ++i) {
					eh->ethr_shost[i] = interface_mac_to_next_hop[i];
					eh->ethr_dhost[i] = 0xFF;
				}

				struct arp_hdr *ah = (struct arp_hdr*)(arp_request + sizeof(struct ether_hdr));
				ah->hw_len = 6;
				ah->proto_len = 4;
				ah->opcode = htons(ARP_REQUEST_OPCODE);
				ah->proto_type = htons(ETHERTYPE_IP);
				ah->hw_type = htons(1);
				ah->tprotoa = rt_entry->next_hop; // its in network byte order
				ah->sprotoa = inet_addr(get_interface_ip(rt_entry->interface));

				for (int i = 0; i < 6; ++i) {
					ah->shwa[i] = interface_mac_to_next_hop[i];
					ah->thwa[i] = 0xFF;
				}
				send_to_link(arp_req_len, arp_request, rt_entry->interface);
				free(arp_request);
				continue;
			}

			uint8_t *mac_next_hop = at_entry->mac;

			uint8_t interface_mac_to_next_hop[6];
			get_interface_mac(rt_entry->interface, interface_mac_to_next_hop);

			for (int i = 0; i < 6; ++i) {
				eh->ethr_shost[i] = interface_mac_to_next_hop[i];
				eh->ethr_dhost[i] = mac_next_hop[i];
			}

			send_to_link(len, buf, rt_entry->interface);
		}
		else if (ether_type == ETHERTYPE_ARP) {
			struct arp_hdr *ah = (struct arp_hdr*)(buf + sizeof(struct ether_hdr));
			uint16_t opcode = ntohs(ah->opcode);
			
			if (opcode == ARP_REQUEST_OPCODE) {
				in_addr_t int_ip = inet_addr(get_interface_ip(interface));
				uint32_t dest_addr = ah->tprotoa;
				if (int_ip != dest_addr) {
					fprintf(stderr, "Packet dropped, arp request not meant for this address!\n");
					continue;
				}
				ah->tprotoa = ah->sprotoa;
				ah->sprotoa = dest_addr;

				for (int i = 0; i < 6; ++i) {
					ah->thwa[i] = ah->shwa[i];
					ah->shwa[i] = int_mac[i];
				}
				ah->opcode = htons(ARP_REPLY_OPCODE);

				for (int i = 0; i < 6; ++i) {
					eh->ethr_dhost[i] = eh->ethr_shost[i];
					eh->ethr_shost[i] = int_mac[i];
				}

				send_to_link(len, buf, interface);
			}
			else if (opcode == ARP_REPLY_OPCODE) {
				uint8_t arp_entry_mac[6];
				uint32_t arp_entry_ip = ah->sprotoa;

				for (int i = 0; i < 6; ++i) {
					arp_entry_mac[i] = ah->shwa[i];
				}

				if (at_no_entries == at_capacity) {
					at = realloc(at, at_capacity * 2 * sizeof(struct arp_table_entry));
					at_capacity *= 2;
				}
				at[at_no_entries].ip = arp_entry_ip;
				
				for (int i = 0; i < 6; ++i) {
					at[at_no_entries].mac[i] = arp_entry_mac[i];
				}

				++at_no_entries;

				unsigned int waiting_size = queue_size(awaiting_arp_reply_pckts);

				while (waiting_size > 0) {
					char *packet = (char*)queue_deq(awaiting_arp_reply_pckts);
					size_t* len_ptr = (size_t*)queue_deq(awaiting_arp_reply_pckt_szs);

					struct ether_hdr *eh = (struct ether_hdr*)packet;

					struct ip_hdr *ih = (struct ip_hdr*)(packet + sizeof(struct ether_hdr));

					struct route_table_entry* rt_entry = search_rtable(rt, ih->dest_addr, rt_no_entries);
					struct arp_table_entry *at_entry = search_arp_table(at, rt_entry->next_hop, at_no_entries);
					
					if (at_entry == NULL) {
						queue_enq(awaiting_arp_reply_pckts, packet);
						queue_enq(awaiting_arp_reply_pckt_szs, len_ptr);
					}
					else {
						uint8_t *mac_next_hop = at_entry->mac;
						uint8_t interface_mac_to_next_hop[6];
						get_interface_mac(rt_entry->interface, interface_mac_to_next_hop);

						for (int i = 0; i < 6; ++i) {
							eh->ethr_shost[i] = interface_mac_to_next_hop[i];
							eh->ethr_dhost[i] = mac_next_hop[i];
						}

						send_to_link(*len_ptr, packet, rt_entry->interface);
						free(packet);
						free(len_ptr);
					}

					--waiting_size;
				}
			}
		}

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

