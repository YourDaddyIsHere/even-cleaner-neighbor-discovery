from random import random
from struct import pack, unpack_from, Struct,calcsize
from socket import inet_ntoa, inet_aton
from HalfBlockDatabase import HalfBlock,HalfBlockDatabase,EMPTY_PK

HASH_LENGTH = 32
SIG_LENGTH = 64
PK_LENGTH = 74

EMPTY_HASH = '1' * HASH_LENGTH  # Used in a request when the response data is not yet available
GENESIS_ID = '0' * HASH_LENGTH  # ID of the first block of the chain.

# Formatting of the signature packet
# TotalUp TotalDown Sequence_number, previous_hash
append_format = 'Q Q i ' + str(HASH_LENGTH) + 's'
# Up, Down
common_data_format = 'I I'
# [Up, Down,
#  TotalUpRequester, TotalDownRequester, sequence_number_requester, previous_hash_requester,
#  TotalUpResponder, TotalDownResponder, sequence_number_responder, previous_hash_responder]
signature_format = ' '.join(["!", common_data_format, append_format, append_format])
# PK_requester, PK_responder, Up, Down,
# TotalUpRequester, TotalDownRequester, sequence_number_requester, previous_hash_requester, signature_requester
requester_half_format = str(PK_LENGTH) + 's ' + str(PK_LENGTH) + 's ' + common_data_format + \
                        ' ' + append_format + ' ' + str(SIG_LENGTH) + 's '
signature_size = calcsize(signature_format)
append_size = calcsize(append_format)

crawl_request_format = 'i'
crawl_request_size = calcsize(crawl_request_format)

# [signature, pk]
authentication_format = str(PK_LENGTH) + 's ' + str(SIG_LENGTH) + 's '
# [Up, Down, TotalUpRequester, TotalDownRequester, sequence_number_requester, previous_hash_requester,
#   TotalUpResponder, TotalDownResponder, sequence_number_responder, previous_hash_responder,
#   signature_requester, pk_requester, signature_responder, pk_responder]
crawl_response_format = signature_format + authentication_format + authentication_format
crawl_response_size = calcsize(crawl_response_format)

#used for half block protocol
crawl_request_format = "! {0}s I I ".format(PK_LENGTH)
crawl_request_size = calcsize(crawl_request_format)

class Message:
    def __init__(self,neighbor_discovery=None,destination_address=None,source_private_address=None,source_public_address=None,private_introduction_address=None,public_introduction_address=None,
                private_address_to_puncture=None,public_address_to_puncture=None,the_missing_identity=None,key_received=None,requested_sequence_number=None,block=None,identifier=None,global_time=0,signature=None,message_type=None,packet=None,
                sender_identity=None):
        """
        @destination_address:the address that this message should be sent to, it is used for the receiver to do public address vote
        @source_private_address:the private address pair of the message sender
        @source_public_address:the public address pair of the message sender
        @private_introduction_address:the private address of a neighbor that we want to introduce to other guys
        @public_introduction_address:the public address of a neighbor that we want to introduce to other guys
        @private_address_to_puncture: as its name
        @public_address_to_puncture:as its name
        @identifier:the ID of the message, it is a 16 bits integer
        @message_type:an integer represents the type of the message, e.g. for introduction-request, the message type is 246
        @packet:the binary string of the message. e.g. when you call encode_introduction_request, it will automatically encode all relevant attributes to binary string and store it in self.packet
        @crypto:it is a dispersy crypto module
        @my_public_key:namely, my public key
        @my_key:it is my private,public key pair
        @my_identity: it is my member id, a member id is a 20 bytes hash of my public key
        @start header:22 bytes string, 1 byte for dispersy version, 1 byte for community version, 20 bytes for master member identity of this community
        @global_time: a integer representing the logical time, similar to lamport clock but with only one dimension
        @the_missing_identity: the member id of the member whose public key we don't have
        """
        self.destination_address = destination_address
        self.source_private_address = source_private_address
        self.source_public_address = source_public_address
        self.private_introduction_address = private_introduction_address
        self.public_introduction_address = public_introduction_address
        self.private_address_to_puncture = private_address_to_puncture
        self.public_address_to_puncture = public_address_to_puncture
        self.identifier = identifier
        self.global_time = global_time
        self.signature = signature
        self.message_type =message_type
        self.packet = packet
        self.the_missing_identity=the_missing_identity
        self.key_received=key_received
        self.sender_identity=sender_identity
        self.requested_sequence_number = requested_sequence_number
        self.block = block

        if neighbor_discovery:
            self.crypto = neighbor_discovery.crypto
            self.my_public_key = neighbor_discovery.my_public_key
            self.my_key = neighbor_discovery.my_key
            self.my_identity = neighbor_discovery.my_identity
            self.start_header = neighbor_discovery.start_header
            self.global_time=neighbor_discovery.global_time

        self.encoder_and_decoder_1Byte = Struct(">B")    #encode/decode bitmap
        self.encoder_and_decoder_3Bytes = Struct(">BH")   #encode/decode as 1byte+2bytes
        self.encoder_and_decoder_2Bytes = Struct(">H")    #encode/decode as 2 bytes
        self.encoder_and_decoder_global_time = Struct(">Q")    #encode/decode time (an integer) as 8bytes
        self.encoder_and_decoder_ip_and_port = Struct(">4sH")    #encode/decode (ip,port) pair
        self._encode_message_map = dict()  # message.name : EncodeFunctions
        self._decode_message_map = dict()  # byte : DecodeFunctions

        self._encode_advice_map = {True: int("1", 2), False: int("0", 2)}
        self._decode_advice_map = dict((value, key) for key, value in self._encode_advice_map.iteritems())
        # reserve 2nd bit for enable/disable sync
        self._encode_sync_map = {True: int("10", 2), False: int("00", 2)}
        self._decode_sync_map = dict((value, key) for key, value in self._encode_sync_map.iteritems())
        # reserve 3rd bit for enable/disable tunnel (02/05/12)
        self._encode_tunnel_map = {True: int("100", 2), False: int("000", 2)}
        self._decode_tunnel_map = dict((value, key) for key, value in self._encode_tunnel_map.iteritems())
        # 4th, 5th and 6th bits are currently unused reserve 7th and 8th bits for connection type
        self._encode_connection_type_map = {u"unknown": int("00000000", 2), u"public": int("10000000", 2), u"symmetric-NAT": int("11000000", 2)}
        self._decode_connection_type_map = dict((value, key) for key, value in self._encode_connection_type_map.iteritems())

    def encode_introduction_request(self):
        #(destination_address,source_private_address,source_public_address)--->self.packet
        assert (self.destination_address != None)
        assert (self.source_private_address != None)
        assert (self.source_public_address != None)
        assert self.global_time != None
        assert self.start_header != None
        assert self.my_identity != None
        assert self.crypto != None
        self.identifier = int(random() * 2 ** 16)
        data = [inet_aton(self.destination_address[0]), self.encoder_and_decoder_2Bytes.pack(self.destination_address[1]),
                inet_aton(self.source_private_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_private_address[1]),
                inet_aton(self.source_public_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_public_address[1]),
                self.encoder_and_decoder_1Byte.pack(self._encode_advice_map[True] | self._encode_connection_type_map[u"unknown"] | self._encode_sync_map[False]),
                self.encoder_and_decoder_2Bytes.pack(self.identifier)]
        container = [self.start_header,chr(246)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature

    def encode_introduction_response(self):
        #(identifier,destination_address,source_private_address,source_public_address,private_introduction_address,public_introduction_address)--->self.packet
        assert self.destination_address != None
        assert self.source_private_address != None
        assert self.source_public_address != None
        assert self.private_introduction_address != None
        assert self.public_introduction_address != None
        assert self.identifier != None
        assert self.global_time != None
        assert self.start_header != None
        assert self.my_identity != None
        assert self.crypto != None
        data = (inet_aton(self.destination_address[0]), self.encoder_and_decoder_2Bytes.pack(self.destination_address[1]),
                inet_aton(self.source_private_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_private_address[1]),
                inet_aton(self.source_public_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_public_address[1]),
                inet_aton(self.private_introduction_address[0]), self.encoder_and_decoder_2Bytes.pack(self.private_introduction_address[1]),
                inet_aton(self.public_introduction_address[0]), self.encoder_and_decoder_2Bytes.pack(self.public_introduction_address[1]),
                self.encoder_and_decoder_1Byte.pack(self._encode_connection_type_map[u"unknown"] | self._encode_tunnel_map[False]),
                self.encoder_and_decoder_2Bytes.pack(self.identifier))
        container = [self.start_header,chr(245)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature

    def encode_puncture_request(self):
        #(private_address_to_puncture,public_address_to_puncture)--->self.packet
        assert self.private_address_to_puncture != None
        assert self.public_address_to_puncture != None
        assert self.global_time != None
        assert self.start_header != None
        assert self.my_identity != None
        assert self.crypto != None
        self.identifier = int(random() * 2 ** 16)
        data = (inet_aton(self.private_address_to_puncture[0]), self.encoder_and_decoder_2Bytes.pack(self.private_address_to_puncture[1]),
                inet_aton(self.public_address_to_puncture[0]), self.encoder_and_decoder_2Bytes.pack(self.public_address_to_puncture[1]),
                self.encoder_and_decoder_2Bytes.pack(self.identifier))
        container = [self.start_header,chr(250)]
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        #since it uses NoAuthentication, the signiture is ""
        signature =""
        self.packet = packet+signature

    def encode_puncture(self):
        #(source_private_address,source_public_address)--->self.packet
        assert self.source_private_address != None
        assert self.source_public_address != None
        #assert self.identifier != None
        assert self.global_time != None
        assert self.start_header != None
        assert self.my_identity != None
        assert self.crypto != None
        identifier = int(random() * 2 ** 16)
        data = (inet_aton(self.source_private_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_private_address[1]),
                inet_aton(self.source_public_address[0]), self.encoder_and_decoder_2Bytes.pack(self.source_public_address[1]),
                self.encoder_and_decoder_2Bytes.pack(identifier))
        container = [self.start_header,chr(249)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature

    def encode_identity(self):
        #()--->self.packet
        assert self.my_public_key!= None
        assert self.global_time!=None
        assert self.start_header != None
        assert self.crypto != None
        self.identifier = int(random() * 2 ** 16)
        container = [self.start_header,chr(248)]
        my_public_key = self.my_public_key
        container.extend((self.encoder_and_decoder_2Bytes.pack(len(my_public_key)), my_public_key))
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        data=()
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet+signature

    """
    def encode_crawl_request(self):
        #the payload of crawl_request is a sequence_number S
        #the receiver will send its blocks whose sequence_number is greater than S
        data = pack("i", self.requested_sequence_number)
        container = [self.start_header,chr(2)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature


    def encode_crawl_response(self):

        data = pack(crawl_response_format, *(self.block.up, self.block.down,
                                         self.block.total_up_requester, self.block.total_down_requester,
                                         self.block.sequence_number_requester, self.block.previous_hash_requester,
                                         self.block.total_up_responder, self.block.total_down_responder,
                                         self.block.sequence_number_responder, self.block.previous_hash_responder,
                                         self.block.public_key_requester, self.block.signature_requester,
                                         self.block.public_key_responder, self.block.signature_responder))

        container = [self.start_header,chr(3)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature

    def encode_crawl_resume(self):
        #the payload(content) of crawl-resume is nothing
        #the only thing we want to inform the receiver is:
        #this is a crawl-resume, and the identity of the sender is xxxxxxx(i.e. me)
        data='',
        container = [self.start_header,chr(4)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature
    """

    def encode_missing_identity(self):
        #the payload(content) of this message is a identity whose public key we don't know yet
        #we expect the receiver can tell us which public key owns this identity
        #(identity refers to the sha1 digest of a public key)
        assert self.the_missing_identity !=None
        assert self.global_time!=None
        assert self.start_header != None
        data = self.the_missing_identity
        container = [self.start_header, chr(247)]
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        #since it uses NoAuthentication, the signiture is ""
        signature =""
        self.packet = packet+signature


    def decode_introduction_request(self):
        #self.packet --->self.(global_time,destination_address,source_private_address,source_public_address,advice_map,signature,header)
        offset = 23
        if len(self.packet) < offset + 21:
            print("insufficient packet length")
        #MemberAuthentication uses sha1
        member_id = self.packet[offset:offset + 20]
        self.sender_identity=member_id

        #uses directDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+20)
        print("global time is:" + str(self.global_time))

        destination_ip, destination_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+28)
        self.destination_address = (inet_ntoa(destination_ip), destination_port)
        print("destination address is:"+ str(self.destination_address))

        source_private_ip, source_private_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+34)
        self.source_private_address = (inet_ntoa(source_private_ip), source_private_port)
        print("source_lan_address is: "+ str(self.source_private_address))

        source_public_ip, source_public_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+40)
        self.source_public_address = (inet_ntoa(source_public_ip), source_public_port)
        print("source_wan_address is: "+str(self.source_public_address))

        flags, self.identifier = self.encoder_and_decoder_3Bytes.unpack_from(self.packet, offset+46)

        advice = self._decode_advice_map.get(flags & int("1", 2))
        print("advice is: "+str(advice))
        self.signature = self.packet[offset+49:]
        self.start_header = self.packet[0:offset]

    def decode_introduction_response(self):
        #self.packet ---> self.(global_time,destination_address,source_private_address,source_public_address,private_introduction_address,public_introduction_address,identifier,signature,start_header)
        offset = 23
        #introduction request use MemberAuthentication
        member_id = self.packet[offset:offset + 20]
        self.sender_identity=member_id

        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+20)
        print("global time is:" + str(self.global_time))

        destination_ip, destination_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+28)

        self.destination_address = (inet_ntoa(destination_ip), destination_port)
        print("destination address is:"+ str(self.destination_address))

        source_private_ip, source_private_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+34)
        self.source_private_address = (inet_ntoa(source_private_ip), source_private_port)
        print("source_lan_address is: "+ str(self.source_private_address))

        source_public_ip, source_public_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+40)
        self.source_public_address = (inet_ntoa(source_public_ip), source_public_port)
        print("source_wan_address is: "+str(self.source_public_address))

        introduction_private_ip, introduction_private_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+46)
        self.private_introduction_address = (inet_ntoa(introduction_private_ip), introduction_private_port)
        print("lan_introduction_address is: "+str(self.private_introduction_address))

        introduction_public_ip, introduction_public_port = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+52)
        self.public_introduction_address = (inet_ntoa(introduction_public_ip), introduction_public_port)
        print("wan_introduction_address is:" +str(self.public_introduction_address))

        flags, self.identifier, = self.encoder_and_decoder_3Bytes.unpack_from(self.packet, offset+58)

        connection_type = self._decode_connection_type_map.get(flags & int("11000000", 2))
        print("connection type is: "+ str(connection_type))
        if connection_type is None:
            print("Invalid connection type flag")

        tunnel = self._decode_tunnel_map.get(flags & int("100", 2))
        print("tunnel is:" + str(tunnel))
        if self.private_introduction_address==("0.0.0.0",0) and self.public_introduction_address ==("0.0.0.0",0):
            print("it is an empty introduction response")

        self.signature = self.packet[offset+61:]
        self.start_header = self.packet[0:offset]

    def decode_puncture_request(self):
        #self.packet ---> self.(global_time,private_address_to_puncture,public_address_to_puncture,identifier,signature,start_header)
        offset = 23
        #puncture-request uses NoAuthentication
        #puncture-request uses DirectDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset)
        print("global time is:" + str(self.global_time))
        if len(self.packet) < offset + 14:
            print("the length is insufficient")

        private_ip_to_puncture, private_port_to_puncture = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+8)
        self.private_address_to_puncture = (inet_ntoa(private_ip_to_puncture), private_port_to_puncture)
        print("lan_walker_address is: "+ str(self.private_address_to_puncture))

        public_ip_to_puncture, public_port_to_puncture = self.encoder_and_decoder_ip_and_port.unpack_from(self.packet, offset+14)
        self.public_address_to_puncture = (inet_ntoa(public_ip_to_puncture), public_port_to_puncture)
        print("wan_walker_address is: "+ str(self.public_address_to_puncture))

        self.identifier, = self.encoder_and_decoder_2Bytes.unpack_from(self.packet, offset+20)

        self.signiture = self.packet[offset+22:]
        self.start_header = self.packet[0:offset]
    def decode_missing_identity(self):
        #packet ---> global time
        offset = 23
        #missing-identity message us NoAuthentication
        key_length = 0
        #it uses PublicResoulution, so we need to do nothing
        #it uses directDitribution, we need to take out the global time
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet,offset)
        print("the global time is: "+str(self.global_time))

    def decode_identity(self):
        offset = 23
        key_length, = self.encoder_and_decoder_2Bytes.unpack_from(self.packet, offset)
        self.key_received = self.packet[offset+2:offset+2 + key_length]
        global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+2+key_length)
        print("global time is:" + str(global_time))
        self.global_time = global_time

    """
    def decode_crawl_request(self):
        offset = 23
        #MemberAuthentication uses sha1
        member_id = self.packet[offset:offset + 20]
        self.sender_identity = member_id
        #uses directDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+20)
        print("global time is:" + str(self.global_time))
        self.requested_sequence_number = unpack_from("i", self.packet, offset+28)



    def decode_crawl_response(self):
        offset = 23
        #offset = placeholder.offset
        #MemberAuthentication uses sha1
        member_id = self.packet[offset:offset + 20]
        self.sender_identity = member_id
        #uses directDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+20)
        print("global time is:" + str(self.global_time))
        block = HalfBlock()
        block_encoded = unpack_from(crawl_response_format, self.packet, offset+28)
        block.from_payload(block_encoded)
        self.block = block

    def decode_crawl_resume(self):
        offset = 23
        #MemberAuthentication uses sha1
        member_id = self.packet[offset:offset + 20]
        self.sender_identity = member_id
        #uses directDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+20)
        print("global time is:" + str(self.global_time))
    """

    #encode crawl request of half block
    def encode_crawl(self):
        #the payload of crawl_request is a sequence_number S
        #the receiver will send its blocks whose sequence_number is greater than S
        data = pack(crawl_request_format, EMPTY_PK, self.requested_sequence_number, 10),
        container = [self.start_header,chr(2)]
        container.append(self.my_identity)
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signature = self.crypto.create_signature(self.my_key, packet)
        self.packet = packet + signature

    """
    #decode crawl request of half block
    def decode_crawl(self):
        offset = 23
        #MemberAuthentication uses sha1
        member_id = self.packet[offset:offset + 20]
        self.sender_identity = member_id
        #uses directDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset+40)
        print("global time is:" + str(self.global_time))
        who, self.requested_sequence_number, limit = unpack_from(crawl_request_format, self.data, offset)
    """

    """
    def encode_halfblock(self):
        data = self.block.pack()
        container = [self.start_header,chr(1)]
        now = self.encoder_and_decoder_global_time.pack(self.global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        #since it uses NoAuthentication, the signiture is ""
        signature =""
        self.packet = packet+signature
    """

    def decode_halfblock(self):
        #self.packet ---> self.(global_time,private_address_to_puncture,public_address_to_puncture,identifier,signature,start_header)
        offset = 23
        self.start_header = self.packet[0:offset]
        #puncture-request uses NoAuthentication
        #puncture-request uses DirectDistribution
        self.global_time, = self.encoder_and_decoder_global_time.unpack_from(self.packet, offset)
        print("global time is:" + str(self.global_time))
        if len(self.packet) < offset + 14:
            print("the length is insufficient")

        self.block=HalfBlock.unpack(self.packet, offset+8)

