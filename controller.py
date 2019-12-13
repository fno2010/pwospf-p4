import time
import traceback
from datetime import datetime, timedelta
from threading import Thread, Event, Lock
from Queue import Queue

from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP, Raw
from cpu_metadata import CPUMetadata1 as CPUMetadata
from cpu_metadata import TYPE_CPU_METADATA

from mininet.log import lg, LEVELS
from async_sniff import AsyncSniffer
from arp_manager import ARPManager
from pwospf_proto import PWOSPF_Hdr, PWOSPF_Hello, PWOSPF_LSU, PWOSPF_LSA, PROTO_PWOSPF, ALLSPFRouters_Addr
from utils import Graph, ipprefix

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

ICMP_TYPE_ECHO  = 0x08
ICMP_TYPE_REPLY = 0x00

MAX_PENDING_QUEUE_SIZE = 65535

class PendingProcessor(object):
    def __init__(self, sw, timeout=None):
        self.sw = sw
        self.running = False
        self.thread = None
        self.stop_event = Event()
        self.timeout = timeout or self.sw.controller.timeout
        self.pending_queue = Queue(maxsize=MAX_PENDING_QUEUE_SIZE)
        self.lock = Lock()
    
    def _setup_thread(self):
        self.thread = Thread(target=self._run)
        self.thread.setDaemon(True)
    
    def future_send(self, pkt, gateway, expiry):
        self.lock.acquire()
        self.pending_queue.put((pkt, gateway, expiry))
        self.lock.release()
    
    def fetch_packet(self):
        self.lock.acquire()
        pkt, gateway, expiry = self.pending_queue.get()
        self.lock.release()
        return pkt, gateway, expiry
    
    def _run(self):
        self.running = True
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                if not self.pending_queue.empty():
                    pkt, gateway, expiry = self.fetch_packet()
                    if time.time() > expiry:
                        lg.info('Timeout to get ARP\n')
                    else:
                        arp_entry = self.sw.controller.arp_manager.arp_table.get(gateway)
                        if arp_entry is None:
                            self.future_send(pkt, gateway, expiry)
                        else:
                            pkt[Ether].dst = arp_entry['mac']
                            lg.info('%s send out pending packet\n' % self.sw.name)
                            self.sw.controller.send(pkt, pkt[CPUMetadata].egressPort)
        except KeyboardInterrupt:
            pass

    def start(self):
        self._setup_thread()
        self.thread.start()

    def stop(self):
        if self.running:
            self.stop_event.set()
            if self.thread:
                self.thread.join()
                self.running = False
        else:
            lg.warn('Pending Processor has not been started yet')

class PWOSPFLSUManager(object):
    def __init__(self, sw):
        self.sw = sw
        self.running = False
        self.thread = None
        self.stop_event = Event()
        self.lastlsutime = datetime(1900, 1, 1) # very early time
        self.lsdb = dict()
        self.lsulock = Lock()
        self.seq = 0
    
    def _setup_thread(self):
        self.thread = Thread(target=self._run)
        self.thread.setDaemon(True)

    def _run(self):
        self.running = True
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                if datetime.now() >= self.lastlsutime + timedelta(seconds=self.sw.lsunit):
                    self._flood_lsu()
                    self.lastlsutime = datetime.now()
                for rid, lsa in self.lsdb.items():
                    if datetime.now() > lsa['lasttime'] + timedelta(seconds=self.sw.lsunit * 3):
                        # wait for 3 times lsunit and then timeout
                        del self.lsdb[rid]
        except KeyboardInterrupt:
            pass
    
    def _flood_lsu(self):
        lsalist = []
        for p in self.sw.data_ports.values():
            # print(self.sw.name, p.intf.name, p.neighbors)
            if not len(p.neighbors):
                lsalist.append(PWOSPF_LSA(subnet=p.Hex2IP(p.MaskedIPHex()), mask=p.Netmask(), routerid='0.0.0.0'))
            else:
                for neigh in p.neighbors.keys():
                    lsalist.append(PWOSPF_LSA(subnet=p.Hex2IP(p.MaskedIPHex(neigh[1])), mask=p.Netmask(), routerid=neigh[0]))

        lsu_pkt = PWOSPF_Hdr(routerid=self.sw.router_id, areaid=self.sw.area_id) / PWOSPF_LSU(seq=self.seq, lsalist=lsalist)
        eth_pkt_builder = lambda dst: (Ether() / IP(src=self.sw.router_id, dst=dst, proto=PROTO_PWOSPF) / lsu_pkt)
        self.lsulock.acquire()
        self.lsdb[self.sw.router_id] = {
            'seq': self.seq,
            'lasttime': datetime.now(),
            'networks': [(lsa.subnet, lsa.mask, lsa.routerid) for lsa in lsalist]
        }
        self.lsulock.release()
        self.seq += 1
        # self.sw.controller.send(eth_pkt, 1, multicast=True)
        for pn, p in self.sw.data_ports.items():
            for neigh in p.neighbors.keys():
                self.sw.controller.send(eth_pkt_builder(neigh[1]), pn)

    def start(self):
        self._setup_thread()
        self.thread.start()
    
    def handleLSU(self, pkt):
        """
        Handling Incoming LSU Packets

        Each received LSU packet must go through the following handling procedure.
        If the LSU was originally generated by the incoming router, the packet is
        dropped.  If the sequence number matches that of the last packet received
        from the sending host, the packet is dropped.  If the packet contents are
        equivalent to the contents of the packet last received from the sending host,
        the host's database entry is updated and the packet is ignored.  If the LSU
        is from a host not currently in the database, the packets contents are used
        to update the database and Djikstra's algorithm is used to recompute the
        forwarding table.  Finally, if the LSU data is for a host currently in the
        database but the information has changed, the LSU is used to update the
        database, and Djikstra's algorithm is run to recompute the forwarding table.

        All received packets with new sequence numbers are flooded to all neighbors
        but the incoming neighbor of the packet.  The TTL header is only checked
        in the forwarding stage and should not be considered when handling the packet
        locally.  The TTL field of all flooded packets must be decremented before
        exiting the router.  If the field after decrement is zero or less, the packet
        must not be flooded.
        """
        pwospf_pkt = PWOSPF_Hdr(pkt[Raw])
        rid = pwospf_pkt.routerid
        # check if generated by myself
        if rid == self.sw.router_id:
            return
        # check if new seq
        if rid in self.lsdb and pwospf_pkt[PWOSPF_LSU].seq == self.lsdb[rid]['seq']:
            return
        self.lsulock.acquire()
        try:
            # update lsu in database
            # print(self.sw.name, pwospf_pkt)
            self.lsdb[rid] = {
                'seq': pwospf_pkt[PWOSPF_LSU].seq,
                'lasttime': datetime.now(),
                'networks': [(lsa.subnet, lsa.mask, lsa.routerid) for lsa in pwospf_pkt[PWOSPF_LSU].lsalist]
            }
            # flood received lsu
            pwospf_pkt[PWOSPF_LSU].ttl -= 1
            for pn, p in self.sw.data_ports.items():
                if not p.neighbors:
                    continue
                if pn == pkt[CPUMetadata].ingressPort:
                    continue
                if pwospf_pkt[PWOSPF_LSU].ttl > 0:
                    pkt[Raw].load = pwospf_pkt.build()
                    self.sw.controller.send(pkt, pn)
        except:
            traceback.print_exc()
        # update forwarding table
        try:
            self.updateRoutingTable()
            self.syncRoutingTable()
        except:
            traceback.print_exc()
        # print(self.sw.pwospf_table)
        self.lsulock.release()
    
    def updateRoutingTable(self):
        """
        Update routing table using distributed Djistra algorithm.
        """
        g = Graph()
        networks = {}
        # print(self.sw.name, self.lsdb)
        for rid, lsa in self.lsdb.items():
            for neigh in lsa['networks']:
                # rid, neigh[2]
                subnet, netmask, neighid = neigh
                g.add_edge(rid, neighid)
                netaddr = ipprefix(subnet, netmask)
                if netaddr not in networks:
                    networks[netaddr] = set()
                networks[netaddr].add(rid)
        # print(self.sw.name, g.adj)
        # print(self.sw.name, networks)
        next_hops = g.find_shortest_paths(self.sw.router_id)
        # print(self.sw.name, next_hops)
        for netaddr, nodes in networks.items():
            if len(nodes) == 1:
                dst = nodes.pop()
                if dst == self.sw.router_id:
                    nhop = None
                else:
                    nhop, _ = next_hops.get(dst, (None, None))
            elif len(nodes) == 2:
                n1, n2 = nodes
                if self.sw.router_id in nodes:
                    dst = nhop = (n2 if n1 == self.sw.router_id else n1)
                else:
                    dst = (n1 if next_hops[n1][1] < next_hops[n2][1] else n2)
                    nhop, _ = next_hops[dst]
            for pn, p in self.sw.data_ports.items():
                gateway = p.ownNeigh(nhop)
                if ipprefix(p.IP(), p.Netmask()) == netaddr:
                    gateway = '0.0.0.0'
                if gateway is not None:
                    r = (netaddr, gateway, pn)
                    self.sw.pending_pwospf_table[netaddr] = r
    
    def syncRoutingTable(self):
        """
        Synchronize routing table from memory to data plane.
        """
        for netaddr in self.sw.pending_pwospf_table:
            if netaddr in self.sw.static_routes:
                continue
            r = self.sw.pending_pwospf_table[netaddr]
            if r != self.sw.pwospf_table.get(netaddr):
                if netaddr in self.sw.pwospf_table:
                    self.sw.removeL3Route(netaddr)
                self.sw.addL3Route(r[0], r[2], r[1])
                self.sw.pwospf_table[netaddr] = r
        deleted_routes = [netaddr for netaddr in self.sw.pwospf_table
                          if netaddr not in self.sw.pending_pwospf_table]
        for netaddr in deleted_routes:
            del self.sw.pwospf_table[netaddr]
        self.sw.pending_pwospf_table = dict()
    
    def stop(self):
        if self.running:
            self.stop_event.set()
            if self.thread:
                self.thread.join()
                self.running = False
        else:
            lg.warn('PWOSPF LSU Manager has not been started yet')

class PWOSPFController(Thread):
    def __init__(self, sw, ctrl_port=1, start_wait=1, timeout=1, arp_timeout=600):
        super(PWOSPFController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.timeout = timeout # timeout for pending packet
        self.arp_timeout = arp_timeout # arp entry living time in seconds
        self.iface = sw.intfs[ctrl_port].name
        self.routing_table = dict()
        self.sniffer = None
        self.arp_manager = ARPManager(self.sw)
        self.pwospf_running = False
        self.pwospf_manager = PWOSPFLSUManager(self.sw)
        self.pending_processor = PendingProcessor(self.sw, timeout=self.timeout)

    def onPacket(self, pkt):
        if lg.getEffectiveLevel() <= LEVELS['debug']:
            pkt.show2()
        if CPUMetadata not in pkt:
            lg.warn("Should only receive packets from switch with special header")
            return

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        try:
            if ARP in pkt:
                if pkt[ARP].op == ARP_OP_REPLY:
                    self.arp_manager.updateArpTable(pkt[ARP].psrc, pkt[ARP].hwsrc)
                    # self.send(pkt, 0)
                elif pkt[ARP].op == ARP_OP_REQ:
                    self.arp_manager.updateArpTable(pkt[ARP].psrc, pkt[ARP].hwsrc)
                    self.arpReply(pkt)
            elif IP in pkt:
                is_local_ip = pkt[IP].dst in [p.IP() for p in self.sw.data_ports.values()]
                if pkt[CPUMetadata].ingressPort not in self.sw.data_ports:
                    lg.warn('%s drops a packet received from an invalid port\n' % self.sw.name)
                    return
                elif ICMP in pkt and pkt[ICMP].type == ICMP_TYPE_ECHO and pkt[ICMP].code == 0:
                    lg.info('%s receive ICMP echo to %s:\n' % (self.sw.name, pkt[IP].dst))
                    if lg.getEffectiveLevel() <= LEVELS['debug']:
                        pkt.show()
                    if is_local_ip:
                        # Reply ICMP echo request
                        self.icmpReply(pkt)
                elif pkt[IP].proto == PROTO_PWOSPF:
                    lg.debug('%s received a PWOSPF packet\n' % self.sw.name)
                    try:
                        pwospf_pkt = PWOSPF_Hdr(pkt[Raw])
                    except Exception:
                        lg.debug('%s cannot parse this PWOSPF packet correctly\n' % self.sw.name)
                        return
                    if lg.getEffectiveLevel() <= LEVELS['debug']:
                        pwospf_pkt.show()
                    if pwospf_pkt.areaid != self.sw.area_id:
                        lg.debug('%s drops PWOSPF packet from a different area\n' % self.sw.name)
                        return
                    if pwospf_pkt.routerid == self.sw.router_id:
                        lg.debug('%s drops PWOSPF packet generated by itself\n' % self.sw.name)
                        return
                    if PWOSPF_Hello in pwospf_pkt:
                        inport = self.sw.data_ports[pkt[CPUMetadata].ingressPort]
                        neigh_id = pwospf_pkt[PWOSPF_Hdr].routerid
                        neigh_ip = pkt[IP].src
                        helloint = pwospf_pkt[PWOSPF_Hello].helloint
                        netmask = pwospf_pkt[PWOSPF_Hello].netmask
                        # print(inport.intf.name, neigh_id, neigh_ip, datetime.now(), netmask, helloint)
                        if inport.ownIP(neigh_ip):
                            inport.updateNeigh(neigh_id, neigh_ip, datetime.now(), netmask, helloint)
                        else:
                            lg.debug('%s drop the hello packet from different subnets\n' % self.sw.name)
                        # print(inport.intf.name, inport.neighbors)
                        return
                    if PWOSPF_LSU in pwospf_pkt:
                        self.pwospf_manager.handleLSU(pkt)
                        return
                if not is_local_ip and pkt[CPUMetadata].egressPort not in self.sw.data_ports:
                    lg.warn('%s drops a packet targeting to an invalid port\n' % self.sw.name)
                    return
                else:
                    outport = self.sw.data_ports[pkt[CPUMetadata].egressPort]
                    dstprefix = ipprefix(pkt[IP].dst, outport.Netmask())
                    route = self.sw.pwospf_table.get(dstprefix)
                    # print(dstprefix, route)
                    if route is None:
                        return
                    gateway = route[1]
                    if gateway == '0.0.0.0':
                        gateway = pkt[IP].dst
                    arp_entry = self.arp_manager.arp_table.get(gateway)
                    lg.info('%s prepare ARP entry: %s\n' % (self.sw.name, arp_entry))
                    if arp_entry is None:
                        lg.info('Missing ARP, request first\n')
                        self.arpRequest(gateway, pkt[CPUMetadata].egressPort)
                    self.pending_processor.future_send(pkt, gateway, time.time() + self.timeout)
        except:
            lg.warn('Some exceptions raised when handle the incoming packet; enable debug mode to see details\n')
            if lg.getEffectiveLevel() <= LEVELS['warning']:
                traceback.print_exc()

    def send(self, pkt, output, multicast=0, *args, **override_kwargs):
        # assert CPUMetadata in pkt, "Controller must send packets with special header"
        if Ether not in pkt:
            return
        if CPUMetadata not in pkt:
            pkt.payload = CPUMetadata() / pkt.payload
            pkt.type = TYPE_CPU_METADATA
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].multiCast = multicast
        pkt[CPUMetadata].egressPort = output
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(pkt, *args, **kwargs)
    
    def arpRequest(self, ip, output):
        mac = self.sw.data_ports[output].intf.MAC()
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac) / CPUMetadata() / \
            ARP(hwlen=6, plen=4, op=ARP_OP_REQ, hwsrc=mac,
                psrc=self.sw.data_ports[output].IP(), hwdst='00:00:00:00:00:00', pdst=ip)
        self.send(pkt, output)
    
    def arpReply(self, pkt):
        inport = self.sw.data_ports[pkt[CPUMetadata].ingressPort]
        port_mac = inport.intf.MAC()
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = port_mac
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        origpdst = pkt[ARP].pdst
        pkt[ARP].pdst = pkt[ARP].psrc
        if inport.ownIP(pkt[ARP].pdst):
            pkt[ARP].psrc = inport.IP()
        else:
            pkt[ARP].psrc = origpdst
        pkt[ARP].hwsrc = port_mac
        self.send(pkt, pkt[CPUMetadata].ingressPort)
    
    def icmpReply(self, pkt):
        # Reply ICMP
        pkt[ICMP].type = 0
        pkt[ICMP].chksum = None
        ip_src = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = ip_src
        mac_src = pkt[Ether].src
        pkt[Ether].src = pkt[Ether].dst
        pkt[Ether].dst = mac_src
        lg.info('Send ICMP Reply from %s to port %d:\n' % (self.sw.name, pkt[CPUMetadata].ingressPort))
        if lg.getEffectiveLevel() <= LEVELS['debug']:
            pkt.show()
        self.send(pkt, pkt[CPUMetadata].ingressPort)

    def run(self):
        # listen on control port
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self.onPacket)
        self.sniffer.start()
        self.arp_manager.start()
        self.pwospf_manager.start()
        self.pending_processor.start()
        self.start_all_interfaces()

    def start(self, *args, **kwargs):
        super(PWOSPFController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)
    
    def start_all_interfaces(self):
        """
        Main loop for PWOSPF
        """
        for pn, p in self.sw.data_ports.items():
            p.start(sendp=lambda _pkt, _pn: self.send(_pkt, _pn))

    def join(self, *args, **kwargs):
        if self.sniffer:
            self.sniffer.stop()
        if self.arp_manager:
            self.arp_manager.stop()
        if self.pwospf_manager:
            self.pwospf_manager.stop()
        if self.pending_processor:
            self.pending_processor.stop()
        super(PWOSPFController, self).join(*args, **kwargs)
