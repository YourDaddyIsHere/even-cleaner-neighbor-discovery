import random
import time
from Neighbor import Neighbor
import logging
import os
BASE = os.path.dirname(os.path.abspath(__file__))
#import netaddr

logging.basicConfig(level=logging.DEBUG, filename=os.path.join(BASE, 'logfile'), filemode="a+",format="%(asctime)-15s %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class NeighborGroup:

	def __init__(self,my_public_key=None):
		"""
		@OUTGOING_LIFE_SPAN: the life span of outgoing neighbor
		@INCOMING_LIFE_SPAN: the life span of incoming neighbor
		@INTRO_LIFE_SPAN: the life span of intro neighbor
		@trusted_neighbors_list: the list of trusted neighbor, namely, trackers
		@outgoring_neighbors: a list of outgoing neighbor
		@incoming_neighbors: a list of incoming neighbor
		@intro_neighbors: a list of intro neighbor
		"""
		self.TRUSTED_LIFE_SPAN=57.5
		self.OUTGOING_LIFE_SPAN=57.5
		self.INCOMING_LIFE_SPAN=57.5
		self.INTRO_LIFE_SPAN = 27.5
		self.trusted_neighbors = []
		self.tracker = [] #0.5% probability, this list should never be empty, should contain at least one tracker
		self.outgoing_neighbors = [] #49.75% probability
		self.incoming_neighbors = [] #24.825%probability
		self.intro_neighbors= [] #24.825%probability
		#self.trusted_neighbors.append(Neighbor(("127.0.0.1",1235),("127.0.0.1",1235),"255,255.255.255"))
		self.tracker.append(Neighbor((u"130.161.119.206"      , 6421),(u"130.161.119.206"      , 6421),"255,255.255.255"))
		self.tracker.append(Neighbor((u"130.161.119.206"      , 6422),(u"130.161.119.206"      , 6422),"255,255.255.255"))
		self.tracker.append(Neighbor((u"131.180.27.155"       , 6423),(u"131.180.27.155"       , 6423),"255,255.255.255"))
		self.tracker.append(Neighbor((u"83.149.70.6"          , 6424),(u"83.149.70.6"          , 6424),"255,255.255.255"))
		self.tracker.append(Neighbor((u"95.211.155.142"       , 6427),(u"95.211.155.142"       , 6427),"255,255.255.255"))
		self.tracker.append(Neighbor((u"95.211.155.131"       , 6428),(u"95.211.155.131"       , 6428),"255,255.255.255"))
		self.tracker.append(Neighbor((u"dispersy1.tribler.org", 6421),(u"dispersy1.tribler.org", 6421)))
		self.tracker.append(Neighbor((u"dispersy2.tribler.org", 6422),(u"dispersy2.tribler.org", 6422)))
		self.tracker.append(Neighbor((u"dispersy3.tribler.org", 6423),(u"dispersy3.tribler.org", 6423)))
		self.tracker.append(Neighbor((u"dispersy4.tribler.org", 6424),(u"dispersy4.tribler.org", 6424)))
		self.tracker.append(Neighbor((u"dispersy7.tribler.org", 6427),(u"dispersy7.tribler.org", 6427)))
		self.tracker.append(Neighbor((u"dispersy8.tribler.org", 6428),(u"dispersy8.tribler.org", 6428)))
		self.my_public_key=my_public_key

	def choose_group(self):
		#return one of the group basing on probability,it is possible to return a empty list
		if(len(self.outgoing_neighbors)==0 and len(self.incoming_neighbors)==0 and len(self.intro_neighbors)==0 and len(self.trusted_neighbors)==0):
			return ("tracker",self.tracker)
		num_random = random.random()*1000
		if(num_random>995):
			return ("tracker",self.tracker)
		elif(num_random>600):
			return ("trusted neighbor",self.trusted_neighbors)
		elif(num_random>300):
			return ("outgoing",self.outgoing_neighbors)
		elif(num_random>150):
			return ("incoming",self.incoming_neighbors)
		else:
			return ("intro",self.intro_neighbors)

	#check if the candidate is already in a list
	def is_in_list(self,neighbor,neighbor_list):
		for c in neighbor_list:
			if self.is_same_neighbor(neighbor,c):
				return True
			else:
				continue
		return False

	#check whether the two neighbors are the same
	def is_same_neighbor(self,neighbor1,neighbor2):
		if(neighbor1.get_private_address()==neighbor2.get_private_address() and neighbor1.get_public_address()==neighbor2.get_public_address() and neighbor1.identity == neighbor2.identity):
			return True
		else:
			return False

	def associate_neigbhor_with_public_key(self,private_ip = "0.0.0.0",public_ip = "0.0.0.0",identity = None,public_key= None):
		"""
		because not every message contains public key or its hash, so it is common that we have
		some neighbors without identity or public key (e.g. intro-neighbors)

		for this member, it is not reliable to identify them via public ip and private ip: image that
		two neighbors shares a same public ip or even a private ip (two instances running with different NATs but
		still with a same outmost NAT). Or even worse, the neighbor dosen't report its public and private ip (e.g. 
		dispersy-identity message, in this case, we only know its ip we see, without knowing it is public or private).

		for those neighbors, we don't know their identity so we can't send a missing-identity message, so we will never be
		able to get their public key. Until we walk to them and receive an introduction-response. So, before walking to them,
		we should completely ignore such neighbors, so we can ignore all neighbors in intro_list

		"""
		for neighbor in self.tracker:
			if(neighbor.get_private_ip()==private_ip or neighbor.get_public_ip()==public_ip) or neighbor.identity==identity:
				neighbor.public_key = public_key
				logger.info("public key associated")

		for neighbor in self.incoming_neighbors:
			if(neighbor.get_private_ip()==private_ip or neighbor.get_public_ip()==public_ip) or neighbor.identity==identity:
				neighbor.public_key = public_key
				logger.info("public key associated")

		for neighbor in self.outgoing_neighbors:
			if(neighbor.get_private_ip()==private_ip or neighbor.get_public_ip()==public_ip) or neighbor.identity==identity:
				neighbor.public_key = public_key
				logger.info("public key associated")






	def clean_stale_neighbors(self):
		#clean neighbors if they exceed their life span
		now = time.time()
		outgoing_neighbors_to_remove=[]
		for neighbor in self.outgoing_neighbors:
			if(now-(neighbor.last_outgoing_time)>self.OUTGOING_LIFE_SPAN):
				print "cleaning a time out walk candidate........"+str(neighbor.get_private_address())
				outgoing_neighbors_to_remove.append(neighbor)
		self.outgoing_neighbors =[x for x in self.outgoing_neighbors if x not in outgoing_neighbors_to_remove]

		incoming_neighbors_to_remove =[]
		for neighbor in self.incoming_neighbors:
			if(now-(neighbor.last_incoming_time)>self.INCOMING_LIFE_SPAN):
				print "cleaning a time out stumble candidate........"+str(neighbor.get_private_address())
				incoming_neighbors_to_remove.append(neighbor)
		self.incoming_neighbors = [x for x in self.incoming_neighbors if x not in incoming_neighbors_to_remove]

		intro_neighbors_to_remove =[]
		for neighbor in self.intro_neighbors:
			if(now-(neighbor.last_intro_time)>self.INTRO_LIFE_SPAN):
				intro_neighbors_to_remove.append(neighbor)
		self.intro_neighbors = [x for x in self.intro_neighbors if x not in intro_neighbors_to_remove]

		trusted_neighbors_to_remove =[]
		for neighbor in self.trusted_neighbors:
			if(now-(neighbor.last_trusted_time)>self.TRUSTED_LIFE_SPAN):
				trusted_neighbors_to_remove.append(neighbor)
		self.trusted_neighbors= [x for x in self.trusted_neighbors if x not in trusted_neighbors_to_remove]

	def add_neighbor_to_outgoing_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.tracker) or self.is_in_list(neighbor,self.outgoing_neighbors) or self.is_in_list(neighbor,self.trusted_neighbors)):
			self.outgoing_neighbors.append(neighbor)
		print "the outgoing(walk_list) is now:"
		for neighbor in self.outgoing_neighbors:
			print neighbor.get_public_address()


	def add_neighbor_to_incoming_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.tracker) or self.is_in_list(neighbor,self.outgoing_neighbors) or self.is_in_list(neighbor,self.incoming_neighbors) or self.is_in_list(neighbor,self.trusted_neighbors)):
			self.incoming_neighbors.append(neighbor)
		print "the incoming(stumble_list) is now:"
		for neighbor in self.incoming_neighbors:
			print [neighbor.get_private_address(),neighbor.get_public_address()]


	def add_neighbor_to_intro_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.tracker) or self.is_in_list(neighbor,self.outgoing_neighbors) or self.is_in_list(neighbor,self.incoming_neighbors) or self.is_in_list(neighbor,self.intro_neighbors) or self.is_in_list(neighbor,self.trusted_neighbors)):
			self.intro_neighbors.append(neighbor)
		print "the intro_list is now:"
		for neighbor in self.intro_neighbors:
			print neighbor.get_public_address()

	def add_neighbor_to_trusted_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.tracker) or self.is_in_list(neighbor,self.trusted_neighbors)):
			self.trusted_neighbors.append(neighbor)
		print "the trusted_list is now:"
		for neighbor in self.trusted_neighbors:
			print neighbor.get_public_address()

	def insert_trusted_neighbor(self,Graph,my_public_key):
		#insert member into trusted_neighbor list according to latest Trusted_graph
		#check outgoing neighbors
		for neighbor in self.outgoing_neighbors:
			#if it has public key
			if neighbor.public_key:
				if Graph.has_trust_path(your_node=my_public_key,node_to_be_trusted=neighbor.public_key):
					self.add_neighbor_to_trusted_list(neighbor)
					self.outgoing_neighbors = [x for x in self.outgoing_neighbors if x is not neighbor]
		#check for incoming_neighbors
		for neighbor in self.incoming_neighbors:
			#if it has public key
			if neighbor.public_key:
				if Graph.has_trust_path(your_node=my_public_key,node_to_be_trusted=neighbor.public_key):
					self.add_neighbor_to_trusted_list(neighbor)
					self.incoming_neighbors = [x for x in self.incoming_neighbors if x is not neighbor]
		#we have no way to know the public key of an intro neighbor, ignore them


		pass

	def get_neighbor_to_walk(self):
		self.clean_stale_neighbors()
		neighbors_list =[]
		list_type=""
		while(len(neighbors_list)==0):
			list_type,neighbors_list = self.choose_group()
		random.shuffle(neighbors_list)
		return neighbors_list[0]

	def get_neighbor_to_introduce(self,neighbor):
		self.clean_stale_neighbors()
		neighbors_list = self.tracker+self.outgoing_neighbors+self.incoming_neighbors+self.trusted_neighbors
		if(len(neighbors_list)>0):
			random.shuffle(neighbors_list)
			for n in neighbors_list:
				if(not self.is_same_neighbor(n,neighbor)):
					return n
			return None
		else:
			return None
