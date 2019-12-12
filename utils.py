import heapq
from collections import defaultdict

def ip2hex(ipaddr):
    o1, o2, o3, o4 = (int(x) for x in ipaddr.split('.'))
    iphex = o1
    iphex = iphex*256 + o2
    iphex = iphex*256 + o3
    iphex = iphex*256 + o4
    return iphex

def hex2ip(iphex):
    o4 = iphex % 256
    iphex /= 256
    o3 = iphex % 256
    iphex /= 256
    o2 = iphex % 256
    iphex /= 256
    o1 = iphex % 256
    return '%d.%d.%d.%d' % (o1, o2, o3, o4)

def ipprefix(subnet, netmask):
    maskhex = ip2hex(netmask)
    subnet = hex2ip(ip2hex(subnet) & maskhex)
    prefixlen = 0
    while maskhex:
        maskhex = maskhex << 1
        if maskhex & 0x100000000:
            prefixlen += 1
        else:
            raise Exception('Invalid netmask %s' % netmask)
        maskhex &= 0xffffffff
    return '%s/%d' % (subnet, prefixlen)

class Graph(object):
    def __init__(self):
        self.adj = defaultdict(list)
    
    def add_edge(self, src, dst):
        self.adj[src].append((src, dst))
    
    def find_shortest_paths(self, src):
        """
        Dijkstra algorthm to find single source shortest paths.

        return a dictionary from dst to next_hop
        """
        dist = {src: 0}
        visited = {}
        previous = {}
        queue = []
        heapq.heappush(queue, (dist[src], src))
        while queue:
            distance, curr = heapq.heappop(queue)
            if curr in visited:
                continue
            visited[curr] = True

            for edge in self.adj[curr]:
                relaxed = dist[curr] + 1
                dst = edge[1]
                if dst not in dist or relaxed < dist[dst]:
                    previous[dst] = curr
                    dist[dst] = relaxed
                    heapq.heappush(queue, (dist[dst], dst))
        next_hops = {}
        for dst in previous:
            curr = dst
            while curr in previous:
                next_hop = curr
                curr = previous[curr]
            next_hops[dst] = (next_hop, dist[dst])
        return next_hops