import struct
from copy import deepcopy

from scapy.fields import ByteField, ByteEnumField, LenField, IPField, \
    XShortField, ShortField, LongField, PadField, FieldLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, DestIPField
from scapy.layers.l2 import Ether
from scapy.utils import checksum

PROTO_PWOSPF = 0x59
_PWOSPF_TYPES = {
    1: "Hello",
    4: "LSU"
}
ALLSPFRouters_Addr = '224.0.0.5'

class PWOSPF_Hdr(Packet):
    """
    PWOSPF Packet Header Format

    All PWOSPF packets are encapsulated in a common header that is identical to
    the OSPFv2 header.   Using the OSPFv2 header will allow PWOSPF to converge on
    OSPF compliance in the future and is recognized by protocol analyzers such
    as ethereal which can greatly aid in debugging.  The PWOSPF header is as
    follows:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Version #   |     Type      |         Packet length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Router ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Area ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |             Autype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Version #
        The PWOSPF/OSPF version number.  This specification documents version 2 of
        the protocol.

    Type
        The OSPF packet types are as follows.  The format of each of these
        packet types is described in a succeeding section.

                            Type   Description
                            ________________________________
                            1      Hello
                            4      Link State Update

    Packet length
        The length of the protocol packet in bytes.  This length includes
        the standard OSPF header.

    Router ID
        The Router ID of the packet's source.  In OSPF, the source and
        destination of a routing protocol packet are the two ends of an
        (potential) adjacency.

    Area ID
        A 32 bit number identifying the area that this packet belongs to.
        All OSPF packets are associated with a single area.  Most travel a
        single hop only.

    Checksum
        The standard IP checksum of the entire contents of the packet,
        excluding the 64-bit authentication field.  This checksum is
        calculated as the 16-bit one's complement of the one's complement
        sum of all the 16-bit words in the packet, excepting the
        authentication field.  If the packet's length is not an integral
        number of 16-bit words, the packet is padded with a byte of zero
        before checksumming.

    AuType
        Set to zero in PWOSPF

    Authentication
        Set to zero in PWOSPF
    """
    name = "PWOSPF Header"

    fields_desc = [
        ByteField('version', 2),
        ByteEnumField('type', 1, _PWOSPF_TYPES),
        LenField('len', None, adjust=lambda x: x + 24),
        IPField('routerid', '1.1.1.1'),
        IPField('areaid', '0.0.0.0'),
        XShortField('checksum', None),
        ShortField('autype', 0),
        LongField('authentication', 0)
    ]

    def post_build(self, p, pay):
        # See <http://tools.ietf.org/html/rfc5613>
        p += pay
        if self.checksum is None:
            # Checksum is calculated without authentication data
            # Algorithm is the same as in IP()
            ck = checksum(p[:16] + p[24:])
            p = p[:12] + struct.pack("!H", ck) + p[14:]
        return p

class PWOSPF_Hello(Packet):
    """
    HELLO Packet Format

    Hello packets are PWOSPF packet type 1.  These packets are sent periodically
    on all interfaces in order to establish and maintain neighbor relationships.
    In addition, Hellos broadcast enabling dynamic discovery of neighboring
    routers.

    All routers connected to a common network must agree on certain parameters
    (network mask and helloint).  These parameters are included in Hello packets,
    so that differences can inhibit the forming of neighbor relationships.  A
    full HELLO packet with PWOSPF header is as follows:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Version #   |       1       |         Packet length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Router ID                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Area ID                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |             Autype            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Authentication                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Authentication                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Network Mask                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         HelloInt              |           padding             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Network mask
        The network mask associated with this interface.  For example, if
        the interface is to a class B network whose third byte is used for
        subnetting, the network mask is 0xffffff00.

    HelloInt
        The number of seconds between this router's Hello packets.
    """
    name = "PWOSPF Hello"

    fields_desc = [
        IPField('netmask', '255.255.255.0'),
        ShortField('helloint', 10),
        ShortField('padding', 0)
    ]

class PWOSPF_LSA(Packet):
    """
    Link state advertisements

    Each link state update packet should contain 1 or more link state
    advertisements.  The advertisements are the reachable routes directly
    connected to the advertising router.  Routes are in the form of the subnet,
    mask and router neighor for the attached link. Link state advertisements
    look specifically as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Subnet                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Mask                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Router ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    subnet
        Subnet number of the advertised route.  Note that default routes
        will have a subnet value of 0.0.0.0.

    Mask
        Subnet mask of the advertised route

    Router ID
        ID of the neighboring router on the advertised link.  If there is no
        connected router to the link the RID should be set to 0.
    """
    name = "PWOSPF Link State Advertisement"

    fields_desc = [
        IPField('subnet', '10.0.0.0'),
        IPField('mask', '255.255.255.0'),
        IPField('routerid', '1.1.1.1')
    ]

    def extract_padding(self, s):
        return '', s

class PWOSPF_LSU(Packet):
    """
    LSU Packet Format

    LSU packets implement the flooding of link states and  are used to build and
    maintain the network topology database at each router.  Each link state
    update packet carries a collection of link state advertisements on hop
    further from its origin.  Several link state advertisements may be included
    in a single packet.  A link state packet with full PWOSF header looks as
    follows:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Version #   |       4       |         Packet length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Router ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Area ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |             Autype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Sequence                |          TTL                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      # advertisements                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-                                                            +-+
    |                  Link state advertisements                    |
    +-                                                            +-+
    |                              ...                              |

    Sequence
        Unique sequence number associated with each Link State Updated.
        Incremented by the LSU source for each subsequence updated.  Duplicate
        LSU packets are dropped by the receiver.

    TTL
        Hop limited value decremented each time the packet is forwarded.  The
        TTL value is only considered during packet forwarding and not during
        packet reception.
    # of advertisements
        Total number of link state advertisements contained in the packet
    """
    name = "PWOSPF Link State Update"

    fields_desc = [
        ShortField('seq', 0),
        ShortField('ttl', 32),
        FieldLenField('lsacount', None, fmt='!I', count_of='lsalist'),
        PacketListField('lsalist', None, PWOSPF_LSA,
                        count_from=lambda pkt: pkt.lsacount,
                        length_from=lambda pkt: 12 * pkt.lsacount)
    ]

    def extract_padding(self, s):
        return '', s

# bind_layers(IP, PWOSPF_Hdr, proto=PROTO_PWOSPF)
bind_layers(PWOSPF_Hdr, PWOSPF_Hello, type=1)
bind_layers(PWOSPF_Hdr, PWOSPF_LSU, type=4)
# DestIPField.bind_addr(PWOSPF_Hdr, ALLSPFRouters_Addr)
