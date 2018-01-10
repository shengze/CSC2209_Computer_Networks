/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * sr_protocol.h
 *
 */

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

/* FIXME
 * ohh how lame .. how very, very lame... how can I ever go out in public
 * again?! /mc
 */

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif
#define ICMP_DATA_SIZE 28

/* Structure of a ICMP header
 */
struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t icmp_aux_identifier;

} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;


/* Structure of a type3 ICMP header
 */
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;


/* Structure of a type11 ICMP header
 */
struct sr_icmp_t11_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint32_t unused;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t11_hdr sr_icmp_t11_hdr_t;


/*
 * Structure of an internet header, naked of options.
 */
struct sr_ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#else
#error "Byte ordering ot specified "
#endif
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
  } __attribute__ ((packed)) ;
typedef struct sr_ip_hdr sr_ip_hdr_t;

/*
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;
typedef struct sr_ethernet_hdr sr_ethernet_hdr_t;



enum sr_ip_protocol {
  ip_protocol_icmp = 0x0001,
  ip_protocol_udp = 0x11,
  ip_protocol_tcp = 0x06,
};

enum sr_ethertype {
  ethertype_arp = 0x0806,
  ethertype_ip = 0x0800,
};


enum sr_arp_opcode {
  arp_op_request = 0x0001,
  arp_op_reply = 0x0002,
};

enum sr_arp_hrd_fmt {
  arp_hrd_ethernet = 0x0001,
};

enum time_exceeded {
  time_exceeded_type = 11,
  time_exceeded_code = 0,
};

enum port_unreachable {
  port_unreachable_type = 3,
  port_unreachable_code = 3,
};

enum dest_host_unreachable {
  dest_host_unreachable_type = 3,
  dest_host_unreachable_code = 1,
};

enum dest_net_unreachable {
  dest_net_unreachable_type = 3,
  dest_net_unreachable_code = 0,
};

enum echo_reply {
  echo_reply_type = 0,
  echo_reply_code = 0,
};

enum echo_request {
  icmp_echo_request = 8,
};


struct sr_tcp_psuedo_hdr {
    uint32_t ip_src, ip_dst; /* source and dest address */
    uint8_t reserved;
    uint8_t ip_p;
    uint16_t tcp_len;
} __attribute__ ((packed));
typedef struct sr_tcp_psuedo_hdr sr_tcp_psuedo_hdr_t;

struct sr_arp_hdr
{
    unsigned short  ar_hrd;             /* format of hardware address   */
    unsigned short  ar_pro;             /* format of protocol address   */
    unsigned char   ar_hln;             /* length of hardware address   */
    unsigned char   ar_pln;             /* length of protocol address   */
    unsigned short  ar_op;              /* ARP opcode (command)         */
    unsigned char   ar_sha[ETHER_ADDR_LEN];   /* sender hardware address      */
    uint32_t        ar_sip;             /* sender IP address            */
    unsigned char   ar_tha[ETHER_ADDR_LEN];   /* target hardware address      */
    uint32_t        ar_tip;             /* target IP address            */
} __attribute__ ((packed)) ;
typedef struct sr_arp_hdr sr_arp_hdr_t;

struct sr_tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    unsigned int data_offset:4;
    unsigned int reserved:3;


#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int fin:1;
    unsigned int syn:1;
    unsigned int rst:1;
    unsigned int psh:1;
    unsigned int ack:1;
    unsigned int urg:1;

    unsigned int ece:1;
    unsigned int cwr:1;
    unsigned int ns:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ns:1;
    unsigned int cwr:1;
    unsigned int ece:1;

    unsigned int urg:1;
    unsigned int ack:1;
    unsigned int psh:1;
    unsigned int rst:1;
    unsigned int syn:1;
    unsigned int fin:1;
#endif

    uint16_t window;
    uint16_t tcp_sum;
    uint16_t urg_pointer;
} __attribute__((packed));
typedef struct sr_tcp_hdr sr_tcp_hdr_t;

#define sr_IFACE_NAMELEN 32
#define ETH_HDR 0
#define ARP_PACKET 1
#define IP_PACKET 2
#define ICMP_PACKET 3
#define ICMP_TYPE3_PACKET 4

#endif /* -- SR_PROTOCOL_H -- */
