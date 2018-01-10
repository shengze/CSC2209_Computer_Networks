/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *dstAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(dstAddr, eHdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  uint16_t packet_type = ntohs(((sr_ethernet_hdr_t *)packet)->ether_type);
  if(is_packet_valid(packet, len))
  {
    if(packet_type == ethertype_ip){  /*it is an ip packet*/
      sr_handlepacket_ip(sr, packet, len, interface, eHdr);
    }
    else if(packet_type == ethertype_arp){  /*it is an arp packet*/
      sr_handlepacket_arp(sr, packet, len, interface);
    }
  }
}/* end sr_ForwardPacket */

/*==========Handle ip packet==========*/
void sr_handlepacket_ip(struct sr_instance* sr, 
                        uint8_t * packet, 
                        unsigned int len, 
                        char* interface,
                        sr_ethernet_hdr_t *etherhdr)
{
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_DST = ip_hdr->ip_dst;
  uint32_t ip_SRC = ip_hdr->ip_src;
  struct sr_if *router_if = sr_get_interface_given_ip(sr, ip_DST);

  if(router_if == NULL){
    /*Not for me!*/
    struct sr_rt *lpm_entry = sr_get_lpm_entry(sr->routing_table, ip_DST);
    if(lpm_entry == NULL){
      /*no match entry in routing table, ICMP net unreachable*/
      sr_send_icmp_error(sr, (uint8_t*)ip_hdr, ip_SRC, 3, 0);
    }else{
      /*find match entry in routing table, check if TTL error occurs*/
      ip_hdr->ip_ttl--;
      if(ip_hdr->ip_ttl <= 0){
        sr_send_icmp_error(sr, (uint8_t*)ip_hdr, ip_SRC, 11, 0);
      }else{
        /*no TTL error, check ARP cache*/
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        uint32_t dst_hop_ip = (uint32_t) lpm_entry->gw.s_addr;
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), dst_hop_ip);
        if(arp_entry){
          /*hit entry, send frame to next hop*/
          struct sr_if *source_interface = sr_get_interface(sr, (const char*)(lpm_entry->interface));
          memcpy(etherhdr->ether_dhost, arp_entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(etherhdr->ether_shost, (uint8_t*)source_interface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

          sr_send_packet(sr, packet, len, source_interface->name);
        }else{
	  /*miss entry, put request into queue, send ARP request*/
	  struct sr_arpreq *dst_hop_ip_req = sr_arpcache_queuereq(&(sr->cache), dst_hop_ip, packet, len, lpm_entry->interface);
          handle_arpreq(sr, dst_hop_ip_req);
        }
      }
    }
  }else{
    /*It is for me!*/
    uint8_t ipProtocol = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    if(ipProtocol == ip_protocol_icmp){
      int offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
      sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet + offset);
      if(icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0){
        /*it is ICMP echo req, send echo reply*/
        sr_icmp_echo_reply(sr, packet, len, interface, etherhdr, ip_hdr, icmp_hdr);
      }
    }else{
      /*it is TCP/UDP, send ICMP port unreachable*/
      sr_send_icmp_error(sr, (uint8_t*)ip_hdr, ip_SRC, 3, 3);
    }
  }
}

/*==========Handle ARP Packet==========*/
void sr_handlepacket_arp(struct sr_instance *sr,
                         uint8_t *packet,
                         unsigned int len,
                         char * interface)
{
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned short rep_or_req = ntohs(arp_hdr->ar_op);

  unsigned char s_mac_addr[ETHER_ADDR_LEN];
  unsigned char t_mac_addr[ETHER_ADDR_LEN];
  memcpy(s_mac_addr, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(t_mac_addr, arp_hdr->ar_tha, ETHER_ADDR_LEN);
  uint32_t s_ip = arp_hdr->ar_sip;
  uint32_t t_ip = arp_hdr->ar_tip;

  int update_or_not = sr_arpcache_update(&(sr->cache), s_ip);

  if(rep_or_req == arp_op_request){
    /*it is a ARP request*/
    struct sr_if *router_if = sr_get_interface_given_ip(sr, t_ip);
    if(router_if != 0){
      /*Yes, the ARP request is exactly for me*/
      if(update_or_not == 0){
        /*no such entry in arp cache, add the entry*/
        sr_arpcache_insert(&(sr->cache), s_mac_addr, s_ip);
      }
      memcpy(ether_hdr->ether_shost, (uint8_t*)router_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_dhost, (uint8_t*)s_mac_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha, router_if->addr, ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_tha, s_mac_addr, ETHER_ADDR_LEN);
      arp_hdr->ar_sip = t_ip;
      arp_hdr->ar_tip = s_ip;
      arp_hdr->ar_op = htons(arp_op_reply);

      sr_send_packet(sr, packet, len, router_if->name);
    }
  }else if(rep_or_req == arp_op_reply){
    /*it is a ARP reply*/
    if(update_or_not == 0){
      /*didn't update, because no such entry in arp cache, then add the entry*/
      struct sr_arpreq * arp_req = sr_arpcache_insert(&(sr->cache), s_mac_addr, s_ip);
      if(arp_req != NULL){
        /*send corresponding packet in arp queue waiting for that reply*/
        struct sr_if *router_if = sr_get_interface_given_ip(sr, t_ip);

        struct sr_packet *iterate_queue = arp_req->packets;
        uint8_t *packet_copy;
        sr_ethernet_hdr_t *ehdr;
        while(iterate_queue != NULL){
          ehdr = (sr_ethernet_hdr_t *)iterate_queue->buf;
          memcpy(ehdr->ether_shost, (uint8_t*)router_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(ehdr->ether_dhost, (uint8_t*)s_mac_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
          packet_copy = malloc(sizeof(uint8_t)*iterate_queue->len);
          memcpy(packet_copy, ehdr, sizeof(uint8_t)*iterate_queue->len);

          sr_send_packet(sr, packet_copy, iterate_queue->len, router_if->name);
          iterate_queue = iterate_queue->next;
        }

        sr_arpreq_destroy(&(sr->cache), arp_req);
      }
    }
  }
}

/*=====Send ARP Request=====*/
void sr_send_arpreq(struct sr_instance *sr,
                    uint32_t ip)
{
  int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet_send = malloc(packet_len);
  sr_ethernet_hdr_t *ether_hdr = (struct sr_ethernet_hdr *) packet_send;
  memcpy(ether_hdr->ether_dhost, generate_ethernet_addr(255), ETHER_ADDR_LEN);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet_send + sizeof(sr_ethernet_hdr_t));
  uint8_t *packet_copy;
  struct sr_if *iterate_if = sr->if_list;
  while(iterate_if != NULL){
    memcpy(ether_hdr->ether_shost, (uint8_t*)iterate_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ethertype_arp);

    arp_hdr->ar_hrd = htons(1);
    arp_hdr->ar_pro = htons(2048);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, iterate_if->addr, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha, (char*)generate_ethernet_addr(0), ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iterate_if->ip;
    arp_hdr->ar_tip = ip;

    packet_copy = malloc(packet_len);
    memcpy(packet_copy, ether_hdr, packet_len);
    
    sr_send_packet(sr, packet_copy, packet_len, iterate_if->name);
    iterate_if = iterate_if->next;
  }
}

/*=====Send ICMP Packet=====*/
void sr_send_icmp_error(struct sr_instance *sr,
                        uint8_t *ip_packet,
                        uint32_t ip_DST,
                        uint8_t type,
                        uint8_t code)
{
  struct sr_rt *lpm_entry = sr_get_lpm_entry(sr->routing_table, ip_DST);
  int total_packet = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet_send = malloc(total_packet);

  sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *) packet_send;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet_send + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t * icmp_hdr_3 = (sr_icmp_t3_hdr_t*) (packet_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  ether_hdr->ether_type = htons(ethertype_ip);

  ip_hdr->ip_len = htons(total_packet - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_dst = ip_DST;

  icmp_hdr_3->icmp_type = type;
  icmp_hdr_3->icmp_code = code;
  memcpy(icmp_hdr_3->data, ip_packet, ICMP_DATA_SIZE);
  icmp_hdr_3->icmp_sum = icmp3_cksum(icmp_hdr_3, sizeof(sr_icmp_t3_hdr_t));

  if(lpm_entry != NULL){
    struct sr_if *source_interface = sr_get_interface(sr, lpm_entry->interface);
    uint32_t dst_hop_ip = (uint32_t) lpm_entry->gw.s_addr;
    if(code != 3){
        ip_hdr->ip_src = source_interface->ip;
    }else{
        ip_hdr->ip_src = ((sr_ip_hdr_t *) ip_packet)->ip_dst;
    }
    ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    memcpy(ether_hdr->ether_shost, (uint8_t *) source_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    struct sr_arpentry * arp_entry = sr_arpcache_lookup(&(sr->cache), dst_hop_ip);
    if(arp_entry != NULL){
      memcpy(ether_hdr->ether_dhost, (uint8_t *) arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      sr_send_packet(sr, packet_send, total_packet, source_interface->name);
    }else{
      struct sr_arpreq * arp_req = sr_arpcache_queuereq(&(sr->cache), dst_hop_ip, packet_send, total_packet, source_interface->name);
      handle_arpreq(sr, arp_req);
    }
  }
}

/*=====ICMP echo reply=====*/
void sr_icmp_echo_reply(struct sr_instance* sr,
                        uint8_t * packet,
                        unsigned int len,
                        char* interface,
                        sr_ethernet_hdr_t * ether_hdr,
                        sr_ip_hdr_t * ip_hdr,
                        sr_icmp_hdr_t * icmp_hdr)
{
  int offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, len - offset);
  
  struct sr_if *router_if = sr_get_interface_given_ip(sr, ip_hdr->ip_dst);
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = router_if->ip;
  ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  
  struct sr_rt *lpm_entry = sr_get_lpm_entry(sr->routing_table, ip_hdr->ip_dst);
/*  ip_hdr->ip_ttl--;
  if(ip_hdr->ip_ttl <= 0){
    sr_send_icmp_error(sr, (uint8_t*)ip_hdr, ip_hdr->ip_src, 11, 0);
  }else{*/
    uint32_t dst_hop_ip = (uint32_t) lpm_entry->gw.s_addr;
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), dst_hop_ip);
    if(arp_entry){
      struct sr_if *source_interface = sr_get_interface(sr, (const char*)(lpm_entry->interface));

      memcpy(ether_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_shost, (uint8_t*)source_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

      sr_send_packet(sr, packet, len, interface);
    }else{
      struct sr_arpreq *dst_hop_ip_req = sr_arpcache_queuereq(&(sr->cache), dst_hop_ip, packet, len, lpm_entry->interface);
      handle_arpreq(sr, dst_hop_ip_req);
    }
  
}









