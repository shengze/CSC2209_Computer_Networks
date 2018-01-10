#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

uint32_t ip_cksum(sr_ip_hdr_t *ip_hdr, int len){
  uint16_t old_cksum, new_cksum;
  old_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  new_cksum = cksum(ip_hdr, len);
  ip_hdr->ip_sum = old_cksum;
  return new_cksum;
}

uint32_t icmp_cksum(sr_icmp_hdr_t *icmp_hdr, int len){
  uint16_t old_cksum, new_cksum;
  old_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  new_cksum = cksum(icmp_hdr, len);
  icmp_hdr->icmp_sum = old_cksum;
  return new_cksum;
}

uint32_t icmp3_cksum(sr_icmp_t3_hdr_t *icmp_hdr_3, int len){
  uint16_t old_cksum, new_cksum;
  old_cksum = icmp_hdr_3->icmp_sum;
  icmp_hdr_3->icmp_sum = 0;
  new_cksum = cksum(icmp_hdr_3, len);
  icmp_hdr_3->icmp_sum = old_cksum;
  return new_cksum;
}

uint32_t tcp_cksum(sr_ip_hdr_t *ipHdr, sr_tcp_hdr_t *tcpHdr, int len){
  sr_tcp_psuedo_hdr_t *tcp_psuedoHdr = malloc(sizeof(sr_tcp_psuedo_hdr_t));
  int tcpLen = len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  int tcp_len = sizeof(sr_tcp_psuedo_hdr_t) + tcpLen;
  memset(tcp_psuedoHdr, 0, sizeof(sr_tcp_psuedo_hdr_t));
  tcp_psuedoHdr->ip_src = ipHdr->ip_src;
  tcp_psuedoHdr->ip_dst = ipHdr->ip_dst;
  tcp_psuedoHdr->tcp_len = htons(tcpLen);
  tcp_psuedoHdr->ip_p = ipHdr->ip_p;
  
  uint16_t cksum_ = tcpHdr->sum;
  tcpHdr->sum = 0;
  uint8_t *full_tcp;
  full_tcp = malloc(sizeof(sr_tcp_psuedo_hdr_t) + tcpLen);
  memcpy(full_tcp, (uint8_t *)tcp_psuedoHdr, sizeof(sr_tcp_psuedo_hdr_t));
  memcpy(&(full_tcp[sizeof(sr_tcp_psuedo_hdr_t)]), (uint8_t *)tcpHdr, tcpLen);
  tcpHdr->sum = cksum_;

  uint16_t newCksum;
  newCksum = cksum(full_tcp, tcp_len);
  free(tcp_psuedoHdr);
  free(full_tcp);
  return newCksum;
}

uint8_t *generate_ethernet_addr(uint8_t x){
  int i = 0;
  uint8_t *mac = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  for(i = 0; i < ETHER_ADDR_LEN; i++){
    mac[i] = x;
  }
  return mac;
}

int is_packet_valid(uint8_t *packet, unsigned int len){
  int e_size = sizeof(sr_ethernet_hdr_t);
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t*)packet;
  if(ether_hdr->ether_type == htons(ethertype_arp)){
    e_size += sizeof(sr_arp_hdr_t);
    if(len >= e_size){
      return 1;
    }else{
      return 0;
    }
  }else if(ether_hdr->ether_type == htons(ethertype_ip)){
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet+e_size);
    e_size += sizeof(sr_ip_hdr_t);
    if(len >= e_size){
      if(ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == ip_hdr->ip_sum){
        if(ip_hdr->ip_p == ip_protocol_icmp){
          int offset = e_size;
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet+e_size);
          e_size += sizeof(sr_icmp_hdr_t);
          if(len >= e_size){
            if(icmp_cksum(icmp_hdr, len-offset) == icmp_hdr->icmp_sum){
              return 1;
            }
          }
        }else{
          return 1;
        }
      }
    }
  }
  return 0;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

