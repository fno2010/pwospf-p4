from mininet.link import Intf
from p4_mininet import P4RuntimeSwitch
from p4_program import P4Program

from controller import PWOSPFController

class PWOSPFRouter(P4RuntimeSwitch):
    def __init__(self, *opts, **kwargs):
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

        kwargs.update({
            'enable_grpc': enable_grpc,
            'cli_path': 'simple_switch_CLI',
            'sw_path': sw_path,
            'program': prog,
            'start_controller': True,
        })

        P4RuntimeSwitch.__init__(self, *opts, **kwargs)

    def addDefaultMulticastGroups(self):
        self.flood_mgid = 1
        data_ports = [p for p in self.infs.keys() if p not in [0, self.ctrl_port]]
        self.addMulticastGroup(mgid=self.flood_mgid, ports=data_ports)
        for pt in data_ports:
            flood_ports = [p for p in data_ports if p != pt]
            self.addMulticastGroup(mgid=pt, ports=flood_ports)

    def initTable(self):
        pass

    def start(self, controllers):
        super(PWOSPFRouter, self).start(controllers)
        self.addDefaultMulticastGroups()
        self.initTable()
        self.controller = PWOSPFController(self, **self.ctrl_args)
        self.controller.start()

    def stop(self):
        if self.controller is not None:
            self.controller.join()
        super(PWOSPFRouter, self).stop()
