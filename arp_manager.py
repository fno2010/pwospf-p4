from threading import Thread, Event
from datetime import datetime, timedelta

from mininet.log import lg


class ARPManager(object):
    def __init__(self, sw, arp_timeout=600):
        self.sw = sw
        self.arp_table = dict()
        self.running = False
        self.thread = None
        self.arp_timeout = arp_timeout
        self.stop_event = Event()
    
    def updateArpTable(self, ip, mac):
        write = True
        if ip in self.arp_table:
            if self.arp_table[ip]['mac'] != mac:
                lg.debug('%s cache should be changed. cleanup now.' % ip)
                self.sw.deleteTableEntry(table_name='PWOSPFIngress.arp_table',
                                         match_fields={'meta.gateway': ip})
            else:
                write = False
        self.arp_table[ip] = {
            'mac': mac,
            'expiry': datetime.now() + timedelta(seconds=self.arp_timeout)
        }

        if write:
            self.sw.insertTableEntry(table_name='PWOSPFIngress.arp_table',
                                     match_fields={'meta.gateway': ip},
                                     action_name='PWOSPFIngress.update_dst_mac',
                                     action_params={'dstEth': mac})
    
    def _setup_thread(self):
        self.thread = Thread(target=self._run)
        self.thread.setDaemon(True)
        
    def _run(self):
        self.running = True
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                # Cleanup expired arp entries
                arp_table_snapshot = self.arp_table.copy()
                for ipk in arp_table_snapshot:
                    if ipk not in self.arp_table:
                        continue
                    if self.arp_table[ipk]['expiry'] < datetime.now():
                        lg.debug('%s is expired. cleanup now.' % ipk)
                        del self.arp_table[ipk]
                        self.sw.deleteTableEntry(table_name='PWOSPFIngress.arp_table',
                                                 match_fields={'meta.gateway': ipk})
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
            raise Exception("Not started!")
