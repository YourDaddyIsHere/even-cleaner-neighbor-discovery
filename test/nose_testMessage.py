from random import random
#import unittest  
import sys
sys.path.append("..")
print sys.path
from neighbor_discovery import NeighborDiscover
from struct import pack, unpack_from, Struct
from twisted.internet import reactor
from socket import inet_ntoa, inet_aton
from nose.tools import assert_equals
from Message import Message


neighbor_discovery = NeighborDiscover(port=23334)
class Test_Message:
    def setup(self):
        print ("TestUM:setup() before each test method")
        self.private_ip = neighbor_discovery.private_ip
        self.private_port = neighbor_discovery.private_port
        self.private_addr = neighbor_discovery.private_address
        #we have no knowledge for our wan IP for now.
        self._struct_B = Struct(">B")
        #self._struct_BBH = Struct(">BBH")
        self._struct_BH = Struct(">BH")
        self._struct_H = Struct(">H")
        #self._struct_HH = Struct(">HH")
        #self._struct_LL = Struct(">LL")
        self._struct_Q = Struct(">Q")
        #self._struct_QH = Struct(">QH")
        #self._struct_QL = Struct(">QL")
        #self._struct_QQHHBH = Struct(">QQHHBH")
        #self._struct_ccB = Struct(">ccB")
        self._struct_4SH = Struct(">4sH")

        self._encode_message_map = dict()  # message.name : EncodeFunctions
        self._decode_message_map = dict()  # byte : DecodeFunctions
        # the dispersy-introduction-request and dispersy-introduction-response have several bitfield
        # flags that must be set correctly
        # reserve 1st bit for enable/disable advice
        self._encode_advice_map = {True: int("1", 2), False: int("0", 2)}
        self._decode_advice_map = dict((value, key) for key, value in self._encode_advice_map.iteritems())
        # reserve 2nd bit for enable/disable sync
        self._encode_sync_map = {True: int("10", 2), False: int("00", 2)}
        self._decode_sync_map = dict((value, key) for key, value in self._encode_sync_map.iteritems())
        # reserve 3rd bit for enable/disable tunnel (02/05/12)
        self._encode_tunnel_map = {True: int("100", 2), False: int("000", 2)}
        self._decode_tunnel_map = dict((value, key) for key, value in self._encode_tunnel_map.iteritems())
        # 4th, 5th and 6th bits are currently unused
        # reserve 7th and 8th bits for connection type
        self._encode_connection_type_map = {u"unknown": int("00000000", 2), u"public": int("10000000", 2), u"symmetric-NAT": int("11000000", 2)}
        self._decode_connection_type_map = dict((value, key) for key, value in self._encode_connection_type_map.iteritems())

        self.master_key = "3081a7301006072a8648ce3d020106052b81040027038192000407afa96c83660dccfbf02a45b68f4bc" + \
                     "4957539860a3fe1ad4a18ccbfc2a60af1174e1f5395a7917285d09ab67c3d80c56caf5396fc5b231d84ceac23627" + \
                     "930b4c35cbfce63a49805030dabbe9b5302a966b80eefd7003a0567c65ccec5ecde46520cfe1875b1187d469823d" + \
                     "221417684093f63c33a8ff656331898e4bc853bcfaac49bc0b2a99028195b7c7dca0aea65"
        self.master_key_hex = self.master_key.decode("HEX")

        self.crypto = neighbor_discovery.crypto
        self.ec = neighbor_discovery.ec
        self.key = neighbor_discovery.key
        self.mid = neighbor_discovery.master_identity
        #the dispersy vesion and community version of multichain community version of multichain community in the tracker
        self.dispersy_version = neighbor_discovery.dispersy_version
        self.community_version = neighbor_discovery.community_version
        #create my key in multichain community, and convert it to mid for signiture use
        self.prefix = neighbor_discovery.start_header
        self.my_key = neighbor_discovery.my_key
        self.my_mid = neighbor_discovery.my_identity
        self.my_public_key = neighbor_discovery.my_public_key


        #candidate_to_walk = neighbor_discovery.get_candidate_to_walk()
        #print candidate_to_walk
        #candidate_to_walk_ADDR = candidate_to_walk.get_WAN_ADDR()
        #message_introduction_request = neighbor_discovery.create_introduction_request(candidate_to_walk_ADDR,walker.lan_addr,walker.lan_addr)
        #neighbor_discovery.transport.write(message_introduction_request.packet,candidate_to_walk_ADDR)

    def teardown(self):
        print ("TestUM:teardown() after each test method")

    @classmethod
    def setup_class(cls):
        print ("setup_class() before any methods in this class")
        #cls.walker = Walker(port=23334)

    @classmethod
    def teardown_class(cls):
        print ("teardown_class() after any methods in this class")

    def test_create_introduction_request(self):
        #the following three address are fabricated
        #only for test use
        destination_address = ("8.8.8.8",8)
        source_lan_address = ("192.168.1.200",20000)
        source_wan_address = ("35.1.2.3",20000)
        #use the walker to create a message
        message = Message(neighbor_discovery=neighbor_discovery,source_private_address=source_lan_address,source_public_address = source_wan_address,destination_address = destination_address)
        message.encode_introduction_request()
        #now we create a message using in a KNOWN CORRECT WAY
        identifier = message.identifier
        data = [inet_aton(destination_address[0]), self._struct_H.pack(destination_address[1]),
                inet_aton(source_lan_address[0]), self._struct_H.pack(source_lan_address[1]),
                inet_aton(source_wan_address[0]), self._struct_H.pack(source_wan_address[1]),
                self._struct_B.pack(self._encode_advice_map[True] | self._encode_connection_type_map[u"unknown"] | self._encode_sync_map[False]),
                self._struct_H.pack(identifier)]
        container = [self.prefix,chr(246)]
        #container.append(self.my_mid)
        my_public_key = self.my_public_key
        #container.extend((self._struct_H.pack(len(my_public_key)), my_public_key))
        container.append(self.my_mid)
        #now = int(time())
        now = self._struct_Q.pack(message.global_time)
        container.append(now)
        container.extend(data)
        #print container
        packet = "".join(container)
        packet_len = len(packet)
        signiture = neighbor_discovery.crypto.create_signature(self.my_key, packet)
        packet = packet + signiture
        assert_equals(message.packet[0:packet_len],packet[0:packet_len])
    
    def test_create_introduction_response(self):
        identifier = int(random() * 2 ** 16)
        destination_address = ("8.8.8.8",8)
        source_lan_address = ("192.168.1.200",20000)
        source_wan_address = ("35.1.2.3",20000)
        lan_introduction_address = ("2.2.2.2",2)
        wan_introduction_address = ("3.3.3.3",3)
        data = (inet_aton(destination_address[0]), self._struct_H.pack(destination_address[1]),
                inet_aton(source_lan_address[0]), self._struct_H.pack(source_lan_address[1]),
                inet_aton(source_wan_address[0]), self._struct_H.pack(source_wan_address[1]),
                inet_aton(lan_introduction_address[0]), self._struct_H.pack(lan_introduction_address[1]),
                inet_aton(wan_introduction_address[0]), self._struct_H.pack(wan_introduction_address[1]),
                self._struct_B.pack(self._encode_connection_type_map[u"unknown"] | self._encode_tunnel_map[False]),
                self._struct_H.pack(identifier))
        container = [self.prefix,chr(245)]
        container.append(self.my_mid)
        now = self._struct_Q.pack(neighbor_discovery.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signiture = self.crypto.create_signature(self.my_key, packet)
        packet_len = len(packet)
        packet = packet + signiture

        #message = walker.create_introduction_response(identifier,destination_address,source_lan_address,source_wan_address,lan_introduction_address,wan_introduction_address)
        message = Message(neighbor_discovery=neighbor_discovery,identifier=identifier,source_private_address = source_lan_address,source_public_address=source_wan_address,
                          private_introduction_address=lan_introduction_address,public_introduction_address = wan_introduction_address,destination_address = destination_address)
        message.encode_introduction_response()
        assert_equals(message.packet[0:packet_len],packet[0:packet_len])

    
    def test_create_puncture_request(self):
        lan_walker_addr = ("2.2.2.2",2)
        wan_walker_addr = ("3.3.3.3",3)
        message = Message(neighbor_discovery=neighbor_discovery,private_address_to_puncture=lan_walker_addr,public_address_to_puncture=wan_walker_addr)
        message.encode_puncture_request()
        identifier = message.identifier
        data = (inet_aton(lan_walker_addr[0]), self._struct_H.pack(lan_walker_addr[1]),
                inet_aton(wan_walker_addr[0]), self._struct_H.pack(wan_walker_addr[1]),
                self._struct_H.pack(identifier))
        container = [self.prefix,chr(250)]
        #my_public_key = self.my_public_key
        now = self._struct_Q.pack(message.global_time)
        container.append(now)
        container.extend(data)
        #print container
        packet = "".join(container)
        packet_len = len(packet)
        #since it uses NoAuthentication, the signiture is ""
        signiture =""
        packet = packet+signiture
        assert_equals(message.packet[0:packet_len],packet[0:packet_len])

    
    def test_create_puncture(self):
        pass

    def test_create_identity(self):
        message=Message(neighbor_discovery=neighbor_discovery)
        message.encode_identity()
        container = [self.prefix,chr(248)]
        #for dispersy-identity, it always uses "bin" as encoding
        #regardless of community-version
        my_public_key = self.my_public_key
        container.extend((self._struct_H.pack(len(my_public_key)), my_public_key))
        now = self._struct_Q.pack(message.global_time)
        container.append(now)
        data=()
        container.extend(data)
        packet = "".join(container)
        packet_len = len(packet)
        signiture = self.crypto.create_signature(self.my_key, packet)
        packet = packet+signiture
        assert_equals(message.packet[0:packet_len],packet[0:packet_len])
    
    #now we have finished all encoding function test, we can assume all those functions are correct
    def test_decode_introduction_request(self):
        destination_address = ("8.8.8.8",8)
        source_lan_address = ("192.168.1.200",20000)
        source_wan_address = ("35.1.2.3",20000)
        #use the walker to create a message
        message = Message(neighbor_discovery=neighbor_discovery,destination_address=destination_address,source_private_address=source_lan_address,source_public_address=source_wan_address)
        message.encode_introduction_request()
        message_decode = Message(packet=message.packet)
        message_decode.decode_introduction_request()
        assert_equals(message.destination_address,message_decode.destination_address)
        assert_equals(message.source_private_address,message_decode.source_private_address)
        assert_equals(message.source_public_address,message_decode.source_public_address)
    
    def test_decode_introduction_response(self):
        identifier = int(random() * 2 ** 16)
        destination_address = ("8.8.8.8",8)
        source_lan_address = ("192.168.1.200",20000)
        source_wan_address = ("35.1.2.3",20000)
        lan_introduction_address = ("2.2.2.2",2)
        wan_introduction_address = ("3.3.3.3",3)
        message = Message(neighbor_discovery=neighbor_discovery,identifier=identifier,destination_address=destination_address,source_private_address=source_lan_address,source_public_address=source_wan_address,
                          private_introduction_address=lan_introduction_address,public_introduction_address=wan_introduction_address)
        message.encode_introduction_response()
        message_decode=Message(packet=message.packet)
        message_decode.decode_introduction_response()
        assert_equals(message.destination_address,message_decode.destination_address)
        assert_equals(message.source_private_address,message_decode.source_private_address)
        assert_equals(message.source_public_address,message_decode.source_public_address)
        assert_equals(message.private_introduction_address,message_decode.private_introduction_address)
        assert_equals(message.public_introduction_address,message_decode.public_introduction_address)
    
    def test_decode_puncture_request(self):
        lan_walker_address = ("2.2.2.2",2)
        wan_walker_address = ("3.3.3.3",3)
        #message = walker.create_puncture_request(lan_walker_address,wan_walker_address)
        message=Message(neighbor_discovery=neighbor_discovery,private_address_to_puncture=lan_walker_address,public_address_to_puncture=wan_walker_address)
        message.encode_puncture_request()
        #message_decode = walker.decode_puncture_request(message.packet)
        message_decode=Message(packet=message.packet)
        message_decode.decode_puncture_request()
        assert_equals(message.private_address_to_puncture,message_decode.private_address_to_puncture)
        assert_equals(message.public_address_to_puncture,message_decode.public_address_to_puncture)
    
