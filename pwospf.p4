/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

struct headers {
    ethernet_t        ethernet;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { /* empty */ }

parser PWOSPFParser(packet_in pkt,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            _: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control PWOSPFVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // TODO: Verify checksum when receiving packets
    }
}

control PWOSPFIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action arp_reply(macAddr_t eth) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        macAddr_t originSrcMac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = originSrcMac;

        hdr.arp.opcode = ARP_OP_REPLY;
        hdr.arp.dstEth = hdr.arp.srcEth;
        ipv4Addr_t originDstIP = hdr.arp.dstIP;
        hdr.arp.dstIP = hdr.arp.srcIP;
        hdr.arp.srcEth = eth;
        hdr.arp.srcIP = originDstIP;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table arp_table {
        key = {
            hdr.arp.dstIP: exact;
        }
        actions = {
            arp_reply;
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    apply {
        if (hdr.arp.isValid()) {
            arp_table.apply();
        } else if (hdr.ipv4.isValid()) {
            local_ip_table.apply();
            routing_table.apply();
        }
    }
}

control PWOSPFEgress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {
    apply { /* empty */ }
}

control PWOSPFComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control PWOSPFDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(
    PWOSPFParser(),
    PWOSPFVerifyChecksum(),
    PWOSPFIngress(),
    PWOSPFEgress(),
    PWOSPFComputeChecksum(),
    PWOSPFDeparser()
) main;