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
	// do not ntohl rentry->interface!

	// count lines in routing table file and allocate that many entries
	unsigned int rt_no_entries = count_lines(argv[1]);
	struct route_table_entry *rt = malloc(rt_no_entries * sizeof(*rt));
	read_rtable(argv[1], rt);

	// initially arp table is empty, capacity doubles when no of entries = capacity
	unsigned int at_no_entries = 0;
	unsigned int at_capacity = 1;
	struct arp_table_entry *at = malloc(at_capacity * sizeof(*at));

	// place received packets in queue if no entry for l2 in arp table
	// also make queue for packet sizes as needed for send
	queue awaiting_arp_reply_pckts = create_queue();
	queue awaiting_arp_reply_pckt_szs = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eh = (struct ether_hdr*)buf;
		uint16_t ether_type = ntohs(eh->ethr_type);

		uint8_t int_mac[6];
		get_interface_mac(interface, int_mac);

		if (!l2_valid(eh->ethr_dhost, int_mac)) {
			fprintf(stderr, "Packet dropped, not broadcast nor is router destination\n");
			continue;
		}

		if (ether_type == ETHERTYPE_IP) {
			struct ip_hdr *ih = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
			uint32_t int_ip = inet_addr(get_interface_ip(interface));

			if (ih->dest_addr == int_ip) {
				// router is the destination, received echo request
				// have to send icmp packet with data of previous packet
				size_t echo_reply_len = sizeof(struct ether_hdr) + sizeof (struct ip_hdr) + sizeof(struct icmp_hdr);
				size_t data_len = (len - echo_reply_len);
				echo_reply_len += data_len;
				char *echo_reply = malloc(echo_reply_len * sizeof(*echo_reply));

				struct ether_hdr *echo_reply_eh = (struct ether_hdr*)echo_reply;
				
				make_ether_hdr(echo_reply_eh, eh->ethr_shost, eh->ethr_dhost, htons(ETHERTYPE_IP));

				struct ip_hdr *echo_reply_ih = (struct ip_hdr*)(echo_reply + sizeof(struct ether_hdr));

				make_ip_hdr(echo_reply_ih, ih->source_addr, ih->dest_addr, IP_PROTO_ICMP, 
					htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + data_len));

				struct icmp_hdr *echo_reply_icmph = (struct icmp_hdr*)(echo_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				struct icmp_hdr *echo_request_icmph = (struct icmp_hdr*)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				// setting type 0 for echo reply
				echo_reply_icmph->mtype = 0;
				echo_reply_icmph->mcode = 0;

				// setting same id and seq number as echo request
				echo_reply_icmph->un_t.echo_t.id = echo_request_icmph->un_t.echo_t.id;
				echo_reply_icmph->un_t.echo_t.seq = echo_request_icmph->un_t.echo_t.seq;
				echo_reply_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)echo_reply_icmph, sizeof(struct icmp_hdr));
				echo_reply_icmph->check = htons(checksum_icmp);

				memcpy(echo_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 
					buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), data_len);

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
				size_t time_excd_len = sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				char *time_excd = malloc(time_excd_len * sizeof(*time_excd));

				struct ether_hdr *time_excd_eh = (struct ether_hdr*)time_excd;

				make_ether_hdr(time_excd_eh, eh->ethr_shost, eh->ethr_dhost, htons(ETHERTYPE_IP));

				struct ip_hdr *time_excd_ih = (struct ip_hdr*)(time_excd + sizeof(struct ether_hdr));

				make_ip_hdr(time_excd_ih, ih->source_addr, int_ip, IP_PROTO_ICMP, 
					htons(2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8));

				struct icmp_hdr *time_excd_icmph = (struct icmp_hdr*)(time_excd + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				// setting type 11 for expired ttl icmp
				time_excd_icmph->mtype = 11;
				time_excd_icmph->mcode = 0;
				time_excd_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)time_excd_icmph, sizeof(struct icmp_hdr));
				time_excd_icmph->check = htons(checksum_icmp);

				memcpy(time_excd + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 
					ih, sizeof(struct ip_hdr) + 8);

				send_to_link(time_excd_len, time_excd, interface);
				free(time_excd);
				continue;
			}

			--ih->ttl;

			struct route_table_entry* rt_entry = search_rtable(rt, ih->dest_addr, rt_no_entries);

			if (rt_entry == NULL) {
				// send icmp packet "Destination unreachable"
				size_t dest_unrc_len = sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;
				char *dest_unrc = malloc(dest_unrc_len * sizeof(dest_unrc));

				struct ether_hdr *dest_unrc_eh = (struct ether_hdr*)dest_unrc;

				make_ether_hdr(dest_unrc_eh, eh->ethr_shost, eh->ethr_dhost, htons(ETHERTYPE_IP));

				struct ip_hdr *dest_unrc_ih = (struct ip_hdr*)(dest_unrc + sizeof(struct ether_hdr));

				make_ip_hdr(dest_unrc_ih, ih->source_addr, int_ip, IP_PROTO_ICMP, 
					htons(2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8));

				struct icmp_hdr *dest_unrc_icmph = (struct icmp_hdr*)(dest_unrc + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				// setting type 3 for destination unreachable
				dest_unrc_icmph->mtype = 3;
				dest_unrc_icmph->mcode = 0;
				dest_unrc_icmph->check = 0;
				uint16_t checksum_icmp = checksum((uint16_t*)dest_unrc_icmph, sizeof(struct icmp_hdr));
				dest_unrc_icmph->check = htons(checksum_icmp);

				memcpy(dest_unrc + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ih, sizeof(struct ip_hdr) + 8);

				send_to_link(dest_unrc_len, dest_unrc, interface);
				free(dest_unrc);

				continue;
			}
			
			ih->checksum = 0;
			uint16_t checksum_ttl = checksum((uint16_t*)ih, sizeof(struct ip_hdr));
			ih->checksum = htons(checksum_ttl);

			// rewrite L2 addresses using arp
			struct arp_table_entry *at_entry = search_arp_table(at, rt_entry->next_hop, at_no_entries);
			
			if (at_entry == NULL) {
				char *packet = malloc(MAX_PACKET_LEN * sizeof(*packet));
				memcpy(packet, buf, len);
				size_t* len_ptr = malloc(sizeof(size_t));
				*len_ptr = len;
				queue_enq(awaiting_arp_reply_pckts, packet);
				queue_enq(awaiting_arp_reply_pckt_szs, len_ptr);

				// send query arp packet
				size_t arp_req_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
				char *arp_request = malloc(arp_req_len * sizeof(*arp_request));
				struct ether_hdr *arp_req_eh = (struct ether_hdr*)arp_request;

				uint8_t interface_mac_to_next_hop[6];
				get_interface_mac(rt_entry->interface, interface_mac_to_next_hop);

				make_ether_hdr(arp_req_eh, (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 
					interface_mac_to_next_hop, htons(ETHERTYPE_ARP));

				struct arp_hdr *arp_req_ah = (struct arp_hdr*)(arp_request + sizeof(struct ether_hdr));

				arp_req_ah->proto_type = htons(ETHERTYPE_IP);
				arp_req_ah->hw_type = htons(1);

				make_arp_hdr(arp_req_ah, htons(ARP_REQUEST_OPCODE), rt_entry->next_hop, 
					inet_addr(get_interface_ip(rt_entry->interface)),
					(uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, interface_mac_to_next_hop);

				send_to_link(arp_req_len, arp_request, rt_entry->interface);
				free(arp_request);
				continue;
			}

			uint8_t *mac_next_hop = at_entry->mac;

			uint8_t interface_mac_to_next_hop[6];
			get_interface_mac(rt_entry->interface, interface_mac_to_next_hop);

			make_ether_hdr(eh, mac_next_hop, interface_mac_to_next_hop, htons(ETHERTYPE_IP));

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

