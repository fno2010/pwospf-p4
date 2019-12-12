# patch AsyncSniffer() from scapy 2.4.3

from threading import Thread, Event
from select import select

from scapy.config import conf
from scapy.data import ETH_P_ALL, MTU
from scapy.error import Scapy_Exception
from scapy.plist import PacketList

class AsyncSniffer(object):
    """
    Asynchronous packet sniffer
    (Refer to: https://github.com/secdev/scapy/issues/989#issuecomment-380044430)

    sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args)

    store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
    lfilter: python function applied to each packet to determine
             if further action may be done
    ex: lfilter = lambda x: x.haslayer(Padding)
    stop_event: Event that stops the function when set
    refresh: check stop_event.set() every refresh seconds
    """
    def __init__(self, *args, **kwargs):
        # Store keyword arguments
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.results = None
        self.stop_event = Event()

    def _setup_thread(self):
        # Prepare sniffing thread
        self.thread = Thread(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs
        )
        self.thread.setDaemon(True)

    def _run(self, store=False, prn=None, lfilter=None,
             refresh=.1, *args, **kwargs):
        s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
        lst = []
        self.running = True
        try:
            while True:
                if self.stop_event and self.stop_event.is_set():
                    break
                sel = select([s], [], [], refresh)
                if s in sel[0]:
                    p = s.recv(MTU)
                    if p is None:
                        break
                    if lfilter and not lfilter(p):
                        continue
                    if store:
                        lst.append(p)
                    if prn:
                        r = prn(p)
                        if r is not None:
                            print(r)
        except KeyboardInterrupt:
            pass
        finally:
            s.close()

        self.results = PacketList(lst, "Sniffed")

    def start(self):
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        self.thread.start()

    def stop(self, join=True):
        """Stops AsyncSniffer if not in async mode"""
        if self.running:
            self.stop_event.set()
            if join:
                self.join()
                self.running = False
                return self.results
        else:
            raise Scapy_Exception("Not started !")

    def join(self, *args, **kwargs):
        if self.thread:
            self.thread.join(*args, **kwargs)
