# Pee-Wee OSPF in P4

## Data-Plane Basic Requirements

- [x] Provide a routing table that can store IP address/prefix pairs with
      their associated port and next-hop IP address.
- [x] Provide an ARP table that can store at least 64 entries. This will
      accept an IP address as a search key and will return the associated MAC
      address (if found). This table is modified by the software, which runs its
      own ARP protocol.
- [x] Provide a "local IP address table". This will accept an IP address as a
      search key and will return a signal that indicates whether the correspond
      address was found. This table is used to identify IP addresses that should be
      forwarded to the CPU.
- [x] Decode incoming IP packets and perform the operations required by a
      router. These include (but are not limited to):
  - [x] verify that the existing checksum and TTL are valid
  - [x] look up the next-hop port and IP address in the route table
  - [x] look up the MAC address of the next-hop in the ARP table
  - [x] set the src MAC address based on the port the packet is departing from
  - [x] decrement TTL
  - [x] calculate a new IP checksum
  - [x] transmit the new packet via the appropriate egress port
  - [x] local IP packets (destined for the router) should be sent to the software
  - [x] PWOSPF packets should be sent to the software
  - [x] packets for which no matching entry is found in the routing table should be sent to the software
  - [x] any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
- [x] Provide counters for the following:
  - [x] IP packets
  - [x] ARP packets
  - [x] Packets forwarded to the control-plane

## Control-Plane Basic Requirements

- [x] Sending ARP requests
- [x] Updating entries in the hardware ARP cache
- [x] Timing out entries in the hardware ARP cache
- [ ] Queuing packets pending ARP replies
- [x] Responding to ICMP echo requests
- [ ] Generating ICMP host unreachable packets
- [x] Handling corrupted or otherwise incorrect IP packets
- [x] Building the forwarding table via a dynamic routing protocol (PWOSPF)
- [x] Support static routing table entries in addition to the routes computed by PWOSPF
- [x] Handling all packets addressed directly to the router