import socket
from struct import pack, unpack_from, Struct
import netifaces

def get_private_IP(addr):
    #try to connect to tracker to determine the ip we used
    #because a device may have multiple network interfaces (e.g. a Wifi and wire network while some of them
    #is not connected to public network)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(addr)
    sock_IP = s.getsockname()[0]
    s.close()
    return sock_IP

"""
@staticmethod
def _get_interface_addresses():
        #Yields Interface instances for each available AF_INET interface found.

        #An Interface instance has the following properties:
        #- name          (i.e. "eth0")
        #- address       (i.e. "10.148.3.254")
        #- netmask       (i.e. "255.255.255.0")
        #- broadcast     (i.e. "10.148.3.255")
    class Interface(object):

        def __init__(self, name, address, netmask, broadcast):
            self.name = name
            self.address = address
            self.netmask = netmask
            self.broadcast = broadcast
            self._l_address, = unpack_from(">L", inet_aton(address))
            self._l_netmask, = unpack_from(">L", inet_aton(netmask))

        def __contains__(self, address):
            assert isinstance(address, str), type(address)
            l_address, = unpack_from(">L", inet_aton(address))
            return (l_address & self._l_netmask) == (self._l_address & self._l_netmask)

        def __str__(self):
            return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

        def __repr__(self):
            return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

    try:
        for interface in netifaces.interfaces():
            try:
                addresses = netifaces.ifaddresses(interface)

            except ValueError:
                # some interfaces are given that are invalid, we encountered one called ppp0
                pass

            else:
                for option in addresses.get(netifaces.AF_INET, []):
                    try:
                        yield Interface(interface, option.get("addr"), option.get("netmask"), option.get("broadcast"))

                    except TypeError:
                        # some interfaces have no netmask configured, causing a TypeError when
                        # trying to unpack _l_netmask
                        pass
    except OSError, e:
        #logger = logging.getLogger("dispersy")
        #logger.warning("failed to check network interfaces, error was: %r", e)
        print ("OSError")

"""
