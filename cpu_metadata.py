from scapy.fields import BitField, ByteField, ShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x081a

class CPUMetadata1(Packet):
    """
    header cpu_metadata_t {
        bit<1> fromCpu;
        bit<1> multiCast;
        bit<5> reserved;
        port_t ingressPort;
        bit<16> egressPort;
        bit<16> origEtherType;
    }
    """
    name = "CPUMetadata1"
    fields_desc = [ BitField("fromCpu", 0, 1),
                    BitField("multiCast", 0, 1),
                    BitField("reserved", 0, 5),
                    BitField("ingressPort", 0, 9),
                    ShortField("egressPort", None),
                    ShortField("origEtherType", None)]

bind_layers(Ether, CPUMetadata1, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata1, IP, origEtherType=0x0800)
bind_layers(CPUMetadata1, ARP, origEtherType=0x0806)
