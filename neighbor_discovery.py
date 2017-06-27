from __future__ import print_function
from twisted.internet.protocol import DatagramProtocol
import logging
import socket
from hashlib import sha1
from random import random
from crypto import ECCrypto,LibNaCLSK
from struct import unpack_from
from socket import inet_ntoa, inet_aton
from Neighbor import Neighbor
from Neighbor_group import NeighborGroup
from twisted.internet import task
from twisted.internet import reactor
from struct import pack, unpack_from, Struct
from Message import Message
#from database import Trusted_Walker_Database
from HalfBlockDatabase import HalfBlockDatabase,HalfBlock
import threading
import util
import os
BASE = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(level=logging.DEBUG, filename=os.path.join(BASE, 'logfile'), filemode="a+",format="%(asctime)-15s %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


import sys
if sys.platform == "darwin":
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3

class NeighborDiscover(DatagramProtocol):

    #when run() is called, the startProtocol() will be called, which register the looping call of visit_a_neighbor()
    #visit_a_neighbor() will send a introduction request to a random neighbor
    #when an UDP packet received, the datagramReceived() will be called, which will call a message handling function according to message_type_id

    def __init__(self,port = 25000,is_tracker=False,step_limit=None,neighbor_group=NeighborGroup()):
        self.is_tracker=is_tracker
        #get the network interface which connected to public Internet, (8.8.8.8,8) is the root DNS server
        #so that the network interface connected to it is guranteed to be connected to public Internet
        #private_ip means LAN ip, public_ip means WAN ip
        #limited the amount of steps
        self.step_count = 0
        self.step_limit = step_limit
        self.private_ip = util.get_private_IP(("8.8.8.8",8))
        self.private_port = port
        self.private_address = (self.private_ip,self.private_port)
        #we have no knowledge for our wan IP for now.
        self.public_ip = "0.0.0.0"
        self.public_port =0
        self.public_address = ("0.0.0.0",0)
        self.PUBLIC_ADDRESS_VOTE = dict()
        #NeighborGroup is the module to store, manage, clean the neighbor we discovered
        self.neighbor_group =neighbor_group
        self.global_time=1
        #hard coded master_key for multichain community
        """
        self.master_key = "3081a7301006072a8648ce3d020106052b81040027038192000407afa96c83660dccfbf02a45b68f4bc" + \
                     "4957539860a3fe1ad4a18ccbfc2a60af1174e1f5395a7917285d09ab67c3d80c56caf5396fc5b231d84ceac23627" + \
                     "930b4c35cbfce63a49805030dabbe9b5302a966b80eefd7003a0567c65ccec5ecde46520cfe1875b1187d469823d" + \
                     "221417684093f63c33a8ff656331898e4bc853bcfaac49bc0b2a99028195b7c7dca0aea65"
        """
        self.master_key = "3081a7301006072a8648ce3d020106052b8104002703819200040503dac58c19267f12cb0cf667e480816cd2574acae" \
                     "5293b59d7c3da32e02b4747f7e2e9e9c880d2e5e2ba8b7fcc9892cb39b797ef98483ffd58739ed20990f8e3df7d1ec5" \
                     "a7ad2c0338dc206c4383a943e3e2c682ac4b585880929a947ffd50057b575fc30ec88eada3ce6484e5e4d6fdf41984c" \
                     "d1e51aaacc5f9a51bcc8393aea1f786fc47cbf994cb1339f706df4a"
        self.master_key_hex = self.master_key.decode("HEX")
        self.crypto = ECCrypto()


        self.ec = self.crypto.generate_key(u"medium")
        self.key = self.crypto.key_from_public_bin(self.master_key_hex)
        self.master_identity = self.crypto.key_to_hash(self.key.pub())
        self.dispersy_version = "\x00"
        self.community_version = "\x01"
        #abandom name "prefix", use "header" to replace
        self.start_header = self.dispersy_version+self.community_version+self.master_identity

        if os.path.isfile(os.path.join(BASE, 'ec_multichain.pem')):
            print("key already exists, loading")
            with open(os.path.join(BASE, 'ec_multichain.pem'), 'rb') as keyfile:
                binarykey = keyfile.read()
                self.my_key = LibNaCLSK(binarykey=binarykey)
        else:
            self.my_key = self.crypto.generate_key(u"medium")
        self.my_identity = self.crypto.key_to_hash(self.my_key.pub())
        self.my_public_key = self.crypto.key_to_bin(self.my_key.pub())
        self.reactor = reactor
        self.listening_port=self.reactor.listenUDP(self.private_port, self)
        #self.database = Trusted_Walker_Database()
        self.database = HalfBlockDatabase(my_public_key=self.my_public_key)

    def startProtocol(self):
        #print("neighbor discovery module started")
        #every 5 seconds, we take a step (visit a known neighbor)
        if(self.is_tracker==False):
            loop = task.LoopingCall(self.visit_a_neighbor)
            loop.start(1.0)

    def stopProtocol(self):
        self.database.close()
        self.database.trust_graph.draw_graph()
        print("the trusted list is now:")
        for neighbor in self.neighbor_group.trusted_neighbors:
            print (neighbor.get_private_address())

    #take one step,visit a known neighbor (candidate)
    def visit_a_neighbor(self):
        #NeighborGroup return a neighbor to walk
        #self.neighbor_group.insert_trusted_neighbor(my_public_key=my_public_key,Graph=self.database.TrustGraph)
        neighbor_to_walk = self.neighbor_group.get_neighbor_to_walk()
        neighbor_to_walk_ADDR = neighbor_to_walk.get_public_address()
        #create new Message and specify its  parameter, make it a Introduction Request
        message_introduction_request = Message(neighbor_discovery=self,destination_address=neighbor_to_walk_ADDR,
                                               source_private_address =self.private_address,source_public_address=self.public_address)
        #encode the message to a introduction request, the binary string will be stored at attribute packet
        message_introduction_request.encode_introduction_request()
        #send the introduction request
        self.transport.write(message_introduction_request.packet,neighbor_to_walk_ADDR)
        logger.info("take step to: "+str(neighbor_to_walk_ADDR))

        if self.step_limit:
            self.step_count = self.step_count + 1
            if self.step_count> self.step_limit:
                print("already reach step_limit, stopping")
                self.reactor.stop()



    def datagramReceived(self, data, addr):
        """
        built-in function of twisted.internet.protocol.DatagramProtocol.
        will be call whenever a UDP packet comes in
        """
        print("received data from" +str(addr))
        #now we receive a UDP datagram, call decode_message to decode it
        self.handle_message(data,addr)

    def handle_message(self,packet,addr):
        #call different message handler according to its message_type
        #TODO:we should ask for public key of other members here
        message_type = ord(packet[22])
        logger.info("message id is:"+str(message_type))
        print("message id is:"+str(message_type))
        if message_type == 247:
            print("here is a missing-identity message")
            self.on_missing_identity(packet,addr)
        if message_type == 245:
            print("here is a introduction-response")
            self.on_introduction_response(packet,addr)
        if message_type == 246:
            print("here is a introduction-request")
            self.on_introduction_request(packet,addr)
        if message_type == 250:
            print("here is a puncture request")
            self.on_puncture_request(packet,addr)
        if message_type == 249:
            print("here is a puncture")
        if message_type == 248:
            print("here is an dispersy-identity")
            self.on_identity(packet,addr)
        if message_type == 1:
            print ("here is a halfblock message")
            self.on_halfblock(packet,addr)
        #if message_type == 2:
            #print("here is a crawl_request")
            #self.on_crawl_request(packet,addr)
        #if message_type == 3:
            #print("here is a crawl_response")
            #self.on_crawl_response(packet,addr)
        #if message_type == 4:
            #print("here is a crawl_resume.............................................................:D")
            #self.on_crawl_resume(packet,addr)

    def on_introduction_request(self,packet,addr):
        """
        1.decode a introduction request
        2.introduce a neighbor we known to the requester
        3.send a puncture request to the neighbor we introduce in step 2
        """
        message_request = Message(packet=packet)
        message_request.decode_introduction_request()
        self.global_time = message_request.global_time
        requester_neighbor = Neighbor(message_request.source_private_address,addr,identity = message_request.sender_identity)
        self.neighbor_group.add_neighbor_to_incoming_list(requester_neighbor)
        #do public_address_vote
        self.public_address_vote(message_request.destination_address,addr)
        #we don't have codes to determine whether the candidate is within our lan, so we use wan address.
        #candidate_request = Wcandidate(message_request.source_lan_address,message_request.source_wan_address)
        neighbor_to_introduce = self.neighbor_group.get_neighbor_to_introduce(requester_neighbor)
        if neighbor_to_introduce!=None:
            introduced_private_address = neighbor_to_introduce.get_private_address()
            introduced_public_address = neighbor_to_introduce.get_public_address()
        else:
            introduced_private_address=("0.0.0.0",0)
            introduced_public_address=("0.0.0.0",0)
        message_response = Message(neighbor_discovery=self,identifier=message_request.identifier,destination_address=addr,source_private_address =self.private_address,source_public_address=self.public_address,
                                   private_introduction_address=introduced_private_address,public_introduction_address=introduced_public_address)
        message_response.encode_introduction_response()
        #now it is time to create puncture request
        if neighbor_to_introduce!=None:
            message_puncture_request = Message(neighbor_discovery=self,source_private_address=message_request.source_private_address,source_public_address=message_request.source_public_address,
                                               private_address_to_puncture=message_request.source_private_address,public_address_to_puncture=addr)
            message_puncture_request.encode_puncture_request()
            #send one puncture request to private ip and one puncture request to public ip
            self.transport.write(message_puncture_request.packet,neighbor_to_introduce.get_public_address())
            self.transport.write(message_puncture_request.packet,neighbor_to_introduce.get_public_address())
        self.transport.write(message_response.packet,addr)

    def on_introduction_response(self,packet,addr):
        """
        1.decode a introduction response
        2.do public address vote to determine our public address
        3.add the introduced neighbor to neighbor_group
        """
        message = Message(packet=packet)
        message.decode_introduction_response()
        self.global_time = message.global_time
        self.public_address_vote(message.destination_address,addr)
        message_sender=Neighbor(message.source_private_address,addr,identity = message.sender_identity)
        self.neighbor_group.add_neighbor_to_outgoing_list(message_sender)
        print("the introduced candidate is: "+ str(message.public_introduction_address))
        if message.private_introduction_address!=("0.0.0.0",0) and message.public_introduction_address!=("0.0.0.0",0):
            introduced_neighbor = Neighbor(message.private_introduction_address,message.public_introduction_address)
            self.neighbor_group.add_neighbor_to_intro_list(introduced_neighbor)
            print("new candidate has been added to intro list")
        #send a missing identity by the way
        identity = message.sender_identity
        responder_member = self.database.get_member(identity = identity)
        if responder_member is None:
            message_missing_identity = Message(neighbor_discovery=self,the_missing_identity=message.sender_identity)
            message_missing_identity.encode_missing_identity()
            self.transport.write(message_missing_identity.packet,addr)

        member = self.database.get_member(identity = identity)
        if member is not None:
            print("the member of the introduction response is: "+str(member[0]))
            public_key = member[1]
            requested_sequence_number = self.database.get_latest_sequence_number(public_key=public_key) +1
            #message_crawl_request = Message(neighbor_discovery=self,requested_sequence_number = requested_sequence_number)
            #message_crawl_request.encode_crawl_request()
            message_crawl = Message(neighbor_discovery=self,requested_sequence_number = requested_sequence_number)
            message_crawl.encode_crawl()
            self.transport.write(message_crawl.packet,addr)
            print("crawl sent")

    def on_puncture_request(self,packet,addr):
        """
        1.decode a puncture request and knows which neighbor we should send the puncture to
        2.send a puncture to both private and public address of that neighbor
        """
        message_puncture_request = Message(packet=packet)
        message_puncture_request.decode_puncture_request()
        self.global_time = message_puncture_request.global_time
        private_address_to_puncture = message_puncture_request.private_address_to_puncture
        public_address_to_puncture = message_puncture_request.public_address_to_puncture
        self.public_address = self.get_majority_vote()
        print("the public addr from majority vote is:")
        print(self.public_address)
        message_puncture = Message(neighbor_discovery=self,source_private_address=self.private_address,
                                   source_public_address=self.public_address)
        message_puncture.encode_puncture()
        self.transport.write(message_puncture.packet,private_address_to_puncture)
        self.transport.write(message_puncture.packet,public_address_to_puncture)

    def on_missing_identity(self,packet,addr):
        """
        1.decode a missing identity
        2.send a dispersy-identity message with our public key
        """
        message_missing_identity = Message(packet=packet)
        message_missing_identity.decode_missing_identity()
        self.global_time = message_missing_identity.global_time
        message_identity = Message(neighbor_discovery=self)
        message_identity.encode_identity()
        self.transport.write(message_identity.packet,addr)

    def on_identity(self,packet,addr):
        """
        1.decode a dispersy-identity message
        2.store the public key in the message to our database
        3.associate this key with the candidate
        4.move this candidate to trusted neigbhors list
        """
        message_identity=Message(packet=packet)
        message_identity.decode_identity()
        sender_identity = sha1(message_identity.key_received).digest()
        if(self.database.get_member(public_key=message_identity.key_received)==None):
            self.database.add_member(identity=sender_identity,public_key=message_identity.key_received)
            self.database.add_visit_record(ip = addr[0],port = addr[1],public_key=message_identity.key_received)
            #then send a crawl request
            requested_sequence_number = self.database.get_latest_sequence_number(public_key=message_identity.key_received) +1
            message_crawl = Message(neighbor_discovery=self,requested_sequence_number = requested_sequence_number)
            message_crawl.encode_crawl()
        self.neighbor_group.associate_neigbhor_with_public_key(public_ip=addr,identity=sender_identity,public_key = message_identity.key_received)
        self.neighbor_group.insert_trusted_neighbor(Graph=self.database.trust_graph,my_public_key=self.my_public_key)



    def on_crawl_request(self,packet,addr):
        pass

    def on_crawl_response(self,packet,addr):
        """
        it is a message in old protocol, should we still support old protocol?
        """
        message_crawl_response = Message(packet=packet)
        message_crawl_response.decode_crawl_response()
        block = message_crawl_response.block
        block.show()
        #it is possible that some guys send us a send block twice due to network latency
        #but we add a block to the database without checking whether it is already in the database
        #it is time consuming to check it using SELECT ... WHERE has_requester =? 
        #if a block is already in database, the database will returns a PRIMARY KEY constraint error. It does no harm to us
        self.database.add_block(block)

    def on_halfblock(self,packet,addr):
        """
        decode a halfblock message, store the block inside to our database
        """
        message_crawl_response = Message(packet=packet)
        message_crawl_response.decode_halfblock()
        block = message_crawl_response.block
        #block.show()
        #it is possible that some guys send us a send block twice due to network latency
        #but we add a block to the database without checking whether it is already in the database
        #it is time consuming to check it using SELECT ... WHERE has_requester =? 
        #if a block is already in database, the database will returns a PRIMARY KEY constraint error. It does no harm to us
        self.database.add_block(block)

    """
    def on_crawl_resume(self,packet,addr):
        message_resume = Message(packet=packet)
        message_resume.decode_crawl_resume()
        identity = message_resume.sender_identity
        #now we already have the identity (20bytes hash of public key)
        #we can use it to retrieve public key in the database
        #and get the latest sequence number of this public key
        member = self.database.get_member(identity=identity)
        public_key = str(member[1])
        latest_sequence_number = self.database.get_latest_sequence_number(public_key=public_key)
        message_crawl_request = Message(neighbor_discovery=self,requested_sequence_number=latest_sequence_number+1)
        message_crawl_request.encode_crawl_request()
        self.transport.write(message_crawl_request.packet,addr)
    """

    def public_address_vote(self,address,neighbor_addr):
        """
        1.if the address (which is our public address in the view of another neighbor) of a message isn't in the PUBLIC_ADDRESS_VOTE,
        add the address to it.
        2. if the address is already in PUBLIC_ADDRESS_VOTE, check whether neighbor_addr is in voter list, if not  add it to the list
        """
        assert isinstance(address,tuple),type(address)
        assert isinstance(neighbor_addr,tuple),type(neighbor_addr)
        #@param:addr my address which is perceived by the voter
        #@param:candidate_addr the candidate's (voter) addr
        change_flag = 0
        ip = address[0]
        port = address[1]
        addr = ip+":"+str(port)
        if addr in self.PUBLIC_ADDRESS_VOTE:
            neighbor_vote_list = self.PUBLIC_ADDRESS_VOTE[addr]
            if neighbor_addr not in neighbor_vote_list:
                self.PUBLIC_ADDRESS_VOTE[addr].append(neighbor_addr)
                change_flag = 1
        else:
            self.PUBLIC_ADDRESS_VOTE[addr] = [neighbor_addr]
            change_flag = 1
        #if there is any update in PUBLIC_ADDRESS_VOTE
        if (change_flag == 1):
            new_public_addr = self.get_majority_vote()
            self.public_ip = new_public_addr[0]
            self.public_port=new_public_addr[1]
            self.public_addr = new_public_addr

        #get the majority votes
    def get_majority_vote(self):
        """
        determine our public address by using majority rule on self.PUBLIC_ADDRESS_VOTE
        """
        max_vote = 0
        majority = self.public_ip+":"+str(self.public_port)
        for key in self.PUBLIC_ADDRESS_VOTE:
            num_vote = len(self.PUBLIC_ADDRESS_VOTE[key])
            if num_vote>max_vote:
                majority = key
        majority_list = majority.split(":")
        majority_ip = majority_list[0]
        majority_port = int(majority_list[1])
        return (majority_ip,majority_port)

    #start the neighbor_discovery module(walker)
    def run(self):
        self.reactor.run()

if __name__ == "__main__":
    neighbor_discovery = NeighborDiscover(port=25000,step_limit=10)
    neighbor_discovery.run()
