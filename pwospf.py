from threading import Thread, Event
from time import sleep
from datetime import datetime, timedelta

import grpc
from mininet.link import Intf
from mininet.log import lg
from p4.v1 import p4runtime_pb2
from p4_mininet import P4RuntimeSwitch
from p4_program import P4Program
from p4runtime_lib.error_utils import printGrpcError
from scapy.all import Ether, IP

from pwospf_proto import PWOSPF_Hdr, PWOSPF_Hello, PROTO_PWOSPF, ALLSPFRouters_Addr
from controller import PWOSPFController


class PWOSPFPort(object):
    """
    PWOSPF Interface:

    The interface is a key abstraction in PWOSPF for logically decomposing the
    topology.  Interfaces between neighboring routers are connected by links which
    must have an associated subnet and mask.  All links are assumed to be
    bi-directional.  Note you must support multiple routers connected to a
    single interface, ie. via a hub or switch.
    """

    def __init__(self, intf, sw=None, portn=None, ipaddr='0.0.0.0', netmask=0x00000000, prefixlen=0, helloint=1, defaultPrefixlen=24, **kwargs):
        """
        An interface within a pwospf router is defined by the following values:

        32 bit ip address  - IP address of associated interface
        32 bit mask mask   - subnet mask of assocaited interface
        16 bit helloint    - interval in seconds between HELLO broadcasts
        list [
            32 bit neighbor id - ID of neighboring router.
            32 bit neighbor ip - IP address of neighboring router's interface this
                                interface is directly connected to.
        ]
        """
        self.intf = intf
        self.sw = sw
        self.portn = portn or self.sw.ports[self.intf]
        self.router_id = self.sw.router_id
        self.area_id = self.sw.area_id
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.prefixlen = prefixlen
        self.defaultPrefixlen = defaultPrefixlen
        self.helloint = helloint
        self.neighbors = dict() # (neigh_id, neigh_ip) -> (lasttime, helloint)
        self.thread = None
        self.running = False
        self.stop_event = Event()
        self.lasthellotime = datetime(1900, 1, 1) # very early time

    def config(self, ip=None, helloint=None, **kwargs):
        if '/' in ip:
            self.ipaddr, self.prefixlen = ip.split('/')
            self.prefixlen = int(self.prefixlen)
        else:
            self.ipaddr = ip
            self.prefixlen = self.defaultPrefixlen
        self.netmask = 0xffffffff ^ (0xffffffff >> self.prefixlen)
        if helloint is not None:
            self.helloint = helloint

    def addNeighbor(self, neigh_id, neigh_ip):
        """
        Deprecated
        """
        self.neighbors.append(dict(neigh_id=neigh_id, neigh_ip=neigh_ip))

    def MAC(self):
        return self.intf.MAC()

    def IP(self):
        return str(self.ipaddr)

    def Netmask(self):
        return self.Hex2IP(self.netmask)

    def Hex2IP(self, iphex):
        o4 = iphex % 256
        iphex /= 256
        o3 = iphex % 256
        iphex /= 256
        o2 = iphex % 256
        iphex /= 256
        o1 = iphex % 256
        return '%d.%d.%d.%d' % (o1, o2, o3, o4)

    def IPHex(self, ipaddr=None):
        if ipaddr is None:
            ipaddr = self.ipaddr
        o1, o2, o3, o4 = (int(x) for x in ipaddr.split('.'))
        iphex = o1
        iphex = iphex*256 + o2
        iphex = iphex*256 + o3
        iphex = iphex*256 + o4
        return iphex

    def MaskedIPHex(self, ipaddr=None, netmask=None):
        if netmask is None:
            netmask = self.netmask
        return self.IPHex(ipaddr) & netmask

    def ownIP(self, ipaddr):
        return self.MaskedIPHex(ipaddr) == self.MaskedIPHex()

    def ownNeigh(self, rid):
        for neigh in self.neighbors:
            if neigh[0] == rid:
                return neigh[1]
        return None

    def _setup_thread(self, **kwargs):
        self.thread = Thread(target=self._hello, kwargs=kwargs)
        self.thread.setDaemon(True)

    def start(self, sendp=None):
        if sendp is None:
            raise Exception('Must provide callback function sendp')
        self._setup_thread(sendp=sendp)
        self.thread.start()

    def _hello(self, sendp=None):
        """
        PWOSPF Hello Protocol:

        To discover and maintain the state of available links, a router participating
        in a PWOSPF topology periodically listens for and broadcasts HELLO packets.
        HELLO packets are broadcasted every helloint seconds with a destination
        address of ALLSPFRouters that is defined as "224.0.0.5" (0xe0000005).  This
        implies that all participating routers must be configured to receive and
        process packets sent to ALLSPFRouters.  On receipt of a HELLO packet a router
        may do one of three things.  If the packet is invalid or corrupt the router
        will drop and ignore the packet and optionally log the error.  If the packet
        is from a yet to be identified neighbor and no other neighbors have been
        discovered off of the incoming interface, the router will add the neighbor to
        the interface.  If the packet is from a known neighbor, the router will mark
        the time the packet was received to track the uptime of its neighbor. The
        set of links of routers to neighbors provides the basic connectivity
        information for the full topology.

        PWOSPF routers use HELLO packets to monitor the status of a neighboring
        router.  If a neighboring router does not emit a HELLO packet within
        NEIGHBOR_TIMEOUT seconds (three times the neighbor's HelloInt) of the last HELLO received,
        the router is assumed down, removed from the interface and a link state
        update flood is initiated.  Note that ONLY HELLO packets are used to
        determine link status.  Even in the case where the router is actively routing
        packets and generating link state update packets, if no HELLO packets are
        generated it will be considered disconnected from the topology.

        Start a thread to send pwospf hello packet periodically.

        sendp: callback to send packet
        """
        if sendp is None:
            raise Exception('Must provide callback function sendp')
        self.running = True
        self.stop_event.clear()
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                if datetime.now() >= self.lasthellotime + timedelta(seconds=self.helloint):
                    # generate hello packet
                    hello_pkt = Ether(src=self.MAC(), dst='ff:ff:ff:ff:ff:ff') / \
                        IP(src=self.IP(), dst=ALLSPFRouters_Addr, proto=PROTO_PWOSPF) / \
                        PWOSPF_Hdr(routerid=self.router_id, areaid=self.area_id) / \
                        PWOSPF_Hello(netmask=self.Netmask(), helloint=self.helloint)
                    sendp(hello_pkt, self.portn)
                    self.lasthellotime = datetime.now()
                for neigh, last in self.neighbors.items():
                    if datetime.now() > last[0] + timedelta(seconds=last[1] * 3):
                        # wait for 3 times helloint and then timeout
                        del self.neighbors[neigh]
        except KeyboardInterrupt:
            pass

    def updateNeigh(self, neigh_id, neigh_ip, lasttime, netmask, helloint):
        """
        Handling Incoming HELLO Packets

        This section explains the detailed processing of a received Hello packet.
        The generic input processing of PWOSPF packets will have checked the
        validity of the IP header and the PWOSPF packet header.  Next, the values of
        the Network Mask and HelloInt fields in the received Hello packet must be
        checked against the values configured for the receiving interface.  Any
        mismatch causes processing to stop and the packet to be dropped.  In other
        words, the above fields are really describing the attached network's
        configuration.

        At this point, an attempt is made to match the source of the Hello Packet to
        one of the receiving interface's neighbors.  If the receiving interface is
        a multi-access network (either broadcast or non-broadcast) the source is
        identified by the IP source address found in the Hello's IP header.  The
        interface's current neighbor(s) are contained in the interface's data
        structure.  If the interface does not have a neighbor, a neighbor is created.
        If the interface already has neighbor(s) but none  match the IP of the
        incoming packet, a new neighbor is added. Finally, if the HELLO packet matches
        a current neighbor, the neighbor's "last hello packet received" timer is
        updated.
        """
        if netmask != self.Netmask() or helloint != self.helloint:
            lg.debug('hello packet mismatch')
            return
        self.neighbors[(neigh_id, neigh_ip)] = (lasttime, helloint)

    def stop(self):
        if self.running:
            self.stop_event.set()
            if self.thread:
                self.thread.join()
                self.running = False
        else:
            lg.warn('PWOSPF has not been started yet')

class PWOSPFRouter(P4RuntimeSwitch):
    """
    PWOSPF Router:

    Like OSPF, PWOSPF operates within an "area" of routers, defined by a 32 bit
    value.  A router can only participate in one area at a time.  Each router in
    an area must have a unique 32 bit router ID.  By convention, the IP address
    of the 0th interface is used as the router ID.  0 and 0xffffffff are invalid
    router IDs and can be used internally to mark uninitialized router ID fields.
    """

    def __init__(self, name, router_id='1.1.1.1', area_id='0.0.0.0', lsunit=30,
                 startup_config=dict(), *opts, **kwargs):
        """
        Each router must therefore define the following values:

        32 bit router ID
        32 bit area ID
        16 bit lsuint    - interval in seconds between link state update broadcasts
        List of router interfaces
        """
        self.router_id = str(router_id)
        self.area_id = str(area_id)
        self.lsunit = lsunit
        self.data_ports = dict()
        self.static_routes = dict()
        self.pwospf_table = dict()
        self.pending_pwospf_table = dict()
        self.commands = dict()

        self.controller = None

        prog = kwargs.get('prog')
        if prog is None:
            raise Exception('Must specify p4 program')
        prog = P4Program(prog)

        if prog.version == 14:
            sw_path = 'simple_switch'
            enable_grpc = False
        elif prog.version == 16:
            sw_path = 'simple_switch_grpc'
            enable_grpc = True
        else:
            raise Exception('Switch does not support P4 version %s' % prog.version)

        self.ctrl_args = dict()
        if 'ctrl_args' in kwargs:
            self.ctrl_args = kwargs['ctrl_args']
            del kwargs['ctrl_args']
        self.ctrl_port = self.ctrl_args.get('ctrl_port', 1)

        self.startup_config = startup_config

        kwargs.update({
            'enable_grpc': enable_grpc,
            'cli_path': 'simple_switch_CLI',
            'sw_path': sw_path,
            'program': prog,
            'start_controller': True,
        })

        P4RuntimeSwitch.__init__(self, name, *opts, **kwargs)

    def deleteTableEntry(self, entry=None,
                         table_name=None, match_fields=None, priority=None):
        if entry is not None:
            table_name = entry['table']
            match_fields = entry.get('match') # None if not found
            priority = entry.get('priority')  # None if not found

        table_entry = self.p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            priority=priority)
        try:
            self.WriteTableEntry(table_entry, update_type=p4runtime_pb2.Update.DELETE)
        except grpc.RpcError as e:
            printGrpcError(e)

    def WriteTableEntry(self, table_entry, update_type=None, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if update_type is None:
            update.type = p4runtime_pb2.Update.INSERT
        else:
            update.type = update_type
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print "P4Runtime Write:", request
        else:
            self.sw_conn.client_stub.Write(request)

    def addDefaultMulticastGroups(self):
        self.flood_mgid = 1
        data_ports = list(self.data_ports.keys())
        self.addMulticastGroup(mgid=self.flood_mgid, ports=data_ports)
        for pt in data_ports:
            flood_ports = [p for p in data_ports if p != pt]
            self.addMulticastGroup(mgid=pt, ports=flood_ports)
            self.addMulticastGroup(mgid=pt|0x800, ports=[pt, self.ctrl_port])

    def addL3Route(self, ipprefix, next_hop, gateway):
        ip, prefixlen = ipprefix.split('/')
        self.insertTableEntry(table_name='PWOSPFIngress.routing_table',
                              match_fields={'hdr.ipv4.dstAddr': [ip, int(prefixlen)]},
                              action_name='PWOSPFIngress.ipv4_forward',
                              action_params={'port': next_hop, 'gateway': gateway})

    def removeL3Route(self, ipprefix):
        ip, prefixlen = ipprefix.split('/')
        self.deleteTableEntry(table_name='PWOSPFIngress.routing_table',
                              match_fields={'hdr.ipv4.dstAddr': [ip, int(prefixlen)]})

    def showRXCounters(self):
        print('RX:')
        cpkt, cbyte = self.readCounter('PWOSPFEgress.outputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFIngress.inputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))
        print('RX of IP packets:')
        cpkt, cbyte = self.readCounter('PWOSPFEgress.ipOutputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFIngress.ipInputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))
        print('RX of ARP packets:')
        cpkt, cbyte = self.readCounter('PWOSPFEgress.arpOutputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFIngress.arpInputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))

    def showTXCounters(self):
        print('TX:')
        cpkt, cbyte = self.readCounter('PWOSPFIngress.inputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFEgress.outputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))
        print('TX of IP packets:')
        cpkt, cbyte = self.readCounter('PWOSPFIngress.ipInputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFEgress.ipOutputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))
        print('TX of ARP packets:')
        cpkt, cbyte = self.readCounter('PWOSPFIngress.arpInputCounter', self.ctrl_port)
        print('\tctrl_port: %d pkts, %d bytes' % (cpkt, cbyte))
        for pn in self.data_ports:
            cpkt, cbyte = self.readCounter('PWOSPFEgress.arpOutputCounter', pn)
            print('\t%s: %d pkts, %d bytes' % (self.data_ports[pn].intf.name, cpkt, cbyte))

    def showIPRoute(self):
        print('prefix\tnext-hop\tinterface')
        for route in self.pwospf_table.values():
            print('%s\t%s\t%s' % (route[0], route[1], self.data_ports[route[2]].intf.name))

    def showIPARP(self):
        print('ip address\tmac address')
        arp_table = self.controller.arp_manager.arp_table.copy()
        for ip in arp_table:
            print('%s\t%s' % (ip, arp_table[ip]['mac']))

    def do_show(self, *args, **kwargs):
        usage = (
            "Usage:\n"
            "\tinterface\tinformation of interfaces\n"
            "\tip\tinformation of ip forwarding\n"
        )
        cmd = args[0] if len(args) > 0 else None
        args = args[1:]
        if cmd == 'interface':
            self.do_show_int(*args, **kwargs)
        elif cmd == 'ip':
            self.do_show_ip(*args, **kwargs)
        else:
            print(usage)

    def do_show_int(self, *args, **kwargs):
        usage = (
            "Usage:\n"
            "\ttx\tshow TX statistics\n"
            "\trx\tshow RX statistics\n"
            "\tall\tshow both TX and RX statistics\n"
        )
        cmd = args[0] if len(args) > 0 else None
        if cmd == 'tx':
            self.showTXCounters()
        elif cmd == 'rx':
            self.showRXCounters()
        elif cmd == 'all':
            self.showTXCounters()
            self.showRXCounters()
        else:
            print(usage)

    def do_show_ip(self, *args, **kwargs):
        usage = (
            "Usage:\n"
            "route\tshow routing table\n"
            "arp\tshow arp table\n"
        )
        cmd = args[0] if len(args) > 0 else None
        if cmd == 'route':
            self.showIPRoute()
        elif cmd == 'arp':
            self.showIPARP()
        else:
            print(usage)

    def initTable(self):
        for pn, p in self.data_ports.items():
            # Initialize local arp table
            # self.insertTableEntry(table_name='PWOSPFIngress.local_arp_table',
            #                       match_fields={'standard_metadata.ingress_port': pn,
            #                                     'hdr.arp.dstIP': [p.MaskedIPHex(), p.prefixlen]},
            #                       action_name='PWOSPFIngress.arp_reply_me',
            #                       action_params={'ip': p.IP(), 'eth': p.intf.MAC()})
            # self.insertTableEntry(table_name='PWOSPFIngress.local_arp_table',
            #                       match_fields={'standard_metadata.ingress_port': pn},
            #                       action_name='PWOSPFIngress.arp_reply',
            #                       action_params={'eth': p.intf.MAC()})

            # Initialize local mac table
            self.insertTableEntry(table_name='PWOSPFIngress.local_mac_table',
                                  match_fields={'standard_metadata.egress_spec': pn},
                                  action_name='PWOSPFIngress.update_src_mac',
                                  action_params={'srcEth': p.intf.MAC()})

            # Initialize local ip table
            self.insertTableEntry(table_name='PWOSPFIngress.local_ip_table',
                                  match_fields={'hdr.ipv4.dstAddr': p.IP()},
                                  action_name='PWOSPFIngress.punt',
                                  action_params={})

    def sendCmd(self, *args, **kwargs):
        """
        Override the original sendCmd method.
        """
        if len(args) == 1 and isinstance(args[0], str):
            _args = args[0].split(' ')
            if len(_args) > 0 and _args[0] in self.commands:
                self.commands[_args[0]](*_args[1:], **kwargs)
                return
        super(PWOSPFRouter, self).sendCmd(*args, **kwargs)

    def startup(self):
        """
        Startup configuration of router
        """
        self.data_ports = {
            p: PWOSPFPort(self.intfs[p], sw=self) for p in self.intfs.keys() if p not in [0, self.ctrl_port]
        }
        intf_config = self.startup_config.get('interfaces', dict())
        for p in self.data_ports.keys():
            self.data_ports[p].config(**intf_config.get(str(p), dict()))
        self.static_routes = self.startup_config.get('static_routes', dict())
        for ipprefix, route in self.static_routes.items():
            self.addL3Route(str(ipprefix), route[0], route[1])

    def register_commands(self):
        self.commands['show'] = self.do_show

    def start(self, controllers):
        super(PWOSPFRouter, self).start(controllers)
        self.startup()
        self.addDefaultMulticastGroups()
        self.initTable()
        self.controller = PWOSPFController(self, **self.ctrl_args)
        self.controller.start()
        self.register_commands()

    def stop(self):
        for p in self.data_ports.values():
            p.stop()
        if self.controller is not None:
            self.controller.join()
        super(PWOSPFRouter, self).stop()
