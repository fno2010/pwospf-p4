from threading import Thread, Event
from scapy.all import sniff, sendp
from scapy.all import Packet, Ether, IP, ARP
# from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time

from mininet.log import lg, LEVELS

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class PWOSPFController(Thread):
    def __init__(self, sw, ctrl_port=1, start_wait=0.3):
        super(PWOSPFController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[ctrl_port].name
        self.arp_table = dict()
        self.stop_event = Event()

    def updateArpTable(self, ip, mac):
        if ip in self.arp_table: return

        self.sw.insertTableEntry(table_name='PWOSPFIngress.arp_table',
                match_fields={'hdr.arp.dstIP': [ip]},
                action_name='PWOSPFIngress.arp_reply',
                action_params={'eth': mac})
        self.arp_table[ip] = mac

    # def handleArpRequest(self, pkt):
    #     self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
    #     self.send(pkt)

    def onPacket(self, pkt):
        if lg.getEffectiveLevel() <= LEVELS['debug']:
            pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REPLY:
                self.updateArpTable(pkt[ARP].psrc, pkt[ARP].hwsrc)
                self.send(pkt, pkt[CPUMetadata].ingressPort, multicast=1)

    def send(self, pkt, output, multicast=0, *args, **override_kwargs):
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].multiCast = multicast
        pkt[CPUMetadata].egressPort = output
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(pkt, *args, **kwargs)

    def run(self):
        # listen on control port
        sniff(iface=self.iface, prn=self.onPacket, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(PWOSPFController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPFController, self).join(*args, **kwargs)
