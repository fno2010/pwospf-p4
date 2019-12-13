/* -*- P4_16 -*- */
/***********************************
  Common Packet Headers Definition
************************************/

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_CPU_METADATA = 0x081b;

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t srcEth;
    ipv4Addr_t srcIP;
    macAddr_t dstEth;
    ipv4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header cpu_metadata_t {
    bit<1> fromCpu;
    bit<1> multiCast;
    bit<5> reserved;
    port_t ingressPort;
    bit<16> egressPort;
    bit<16> origEtherType;
}