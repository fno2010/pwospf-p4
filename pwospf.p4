/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

const bit<32> MAX_PORTS = 65;
const port_t CPU_PORT = 0x1;

struct headers {
    ethernet_t        ethernet;
    arp_t             arp;
    ipv4_t            ipv4;
    cpu_metadata_t    cpu_metadata;
}

struct metadata {
    ipv4Addr_t gateway;
}

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
            TYPE_CPU_METADATA: parse_cpu_metadata;
            _: accept;
        }
    }

    state parse_cpu_metadata {
        pkt.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
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
        // Verify checksum when receiving packets
        verify_checksum(
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

control PWOSPFIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {
    counter(MAX_PORTS, CounterType.packets_and_bytes) inputCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ipInputCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) arpInputCounter;

    action drop() {
        mark_to_drop();
    }

    action flood() {
        standard_metadata.mcast_grp = (bit<16>) standard_metadata.ingress_port;
    }

    action mirror() {
        standard_metadata.mcast_grp = (bit<16>) standard_metadata.egress_spec | 0x8000;
    }

    action ipv4_forward(port_t port, ipv4Addr_t gateway) {
        standard_metadata.egress_spec = port;
        meta.gateway = gateway;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action arp_reply(macAddr_t eth) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = eth;

        hdr.arp.opcode = ARP_OP_REPLY;
        hdr.arp.dstEth = hdr.arp.srcEth;
        ipv4Addr_t originDstIP = hdr.arp.dstIP;
        hdr.arp.dstIP = hdr.arp.srcIP;
        hdr.arp.srcEth = eth;
        hdr.arp.srcIP = originDstIP;
    }

    action arp_reply_me(ipv4Addr_t ip, macAddr_t eth) {
        arp_reply(eth);
        hdr.arp.dstIP = ip;
    }

    action punt() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.ingressPort = standard_metadata.ingress_port;
        if (standard_metadata.egress_spec != CPU_PORT) {
            hdr.cpu_metadata.egressPort = (bit<16>) standard_metadata.egress_spec;
        }
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
        standard_metadata.egress_spec = CPU_PORT;
    }

    action sendout() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        if (hdr.cpu_metadata.multiCast == 0x1) {
            standard_metadata.mcast_grp = hdr.cpu_metadata.egressPort;
        } else {
            standard_metadata.egress_spec = (port_t) hdr.cpu_metadata.egressPort;
        }
        hdr.cpu_metadata.setInvalid();
    }

    action update_src_mac(macAddr_t srcEth) {
        hdr.ethernet.srcAddr = srcEth;
    }

    action update_dst_mac(macAddr_t dstEth) {
        hdr.ethernet.dstAddr = dstEth;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table local_mac_table {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            update_src_mac;
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table arp_table {
        key = {
            meta.gateway: exact;
        }
        actions = {
            update_dst_mac;
            drop;
            punt;
            NoAction;
        }
        size = 64;
        default_action = punt();
    }

    // table local_arp_table {
    //     key = {
    //         standard_metadata.ingress_port: exact;
    //         hdr.arp.dstIP: lpm;
    //     }
    //     actions = {
    //         arp_reply;
    //         arp_reply_me;
    //         drop;
    //         NoAction;
    //     }
    //     size = 64;
    //     default_action = drop();
    // }

    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            punt;
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    apply {
        inputCounter.count((bit<32>) standard_metadata.ingress_port);
        if (hdr.cpu_metadata.isValid() && standard_metadata.ingress_port == CPU_PORT) {
            if (hdr.cpu_metadata.egressPort != 0) {
                sendout();
            }
            return;
        } else if (hdr.arp.isValid()) {
            arpInputCounter.count((bit<32>) standard_metadata.ingress_port);
            punt();
            return;
            // if (hdr.arp.opcode == ARP_OP_REQ) {
            //     // Learn arp from req and response to it
            //     local_arp_table.apply();
            //     mirror();
            //     return;
            // } else if (hdr.arp.opcode == ARP_OP_REPLY) {
            //     // Learn arp from reply
            //     punt();
            // }
        } else if (hdr.ipv4.isValid()) {
            ipInputCounter.count((bit<32>) standard_metadata.ingress_port);
            local_ip_table.apply();
            if (hdr.cpu_metadata.isValid()) {
                return;
            }
            if (hdr.ipv4.ttl == 0) {
                drop();
            }
            routing_table.apply();
            if (meta.gateway == 0) {
                meta.gateway = hdr.ipv4.dstAddr;
            }
            arp_table.apply();
            local_mac_table.apply();
            return;
        }
        punt();
    }
}

control PWOSPFEgress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {
    counter(MAX_PORTS, CounterType.packets_and_bytes) outputCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ipOutputCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) arpOutputCounter;

    apply {
        outputCounter.count((bit<32>) standard_metadata.ingress_port);
        if (hdr.arp.isValid()) {
            arpOutputCounter.count((bit<32>) standard_metadata.ingress_port);
        } else if (hdr.ipv4.isValid()) {
            ipOutputCounter.count((bit<32>) standard_metadata.ingress_port);
        }
    }
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
        pkt.emit(hdr.cpu_metadata);
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