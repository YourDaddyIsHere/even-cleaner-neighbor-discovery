import random
import time
from Neighbor import Neighbor
import netaddr

class NeighborGroup:

	def __init__(self):
		"""
		@OUTGOING_LIFE_SPAN: the life span of outgoing neighbor
		@INCOMING_LIFE_SPAN: the life span of incoming neighbor
		@INTRO_LIFE_SPAN: the life span of intro neighbor
		@trusted_neighbors_list: the list of trusted neighbor, namely, trackers
		@outgoring_neighbors: a list of outgoing neighbor
		@incoming_neighbors: a list of incoming neighbor
		@intro_neighbors: a list of intro neighbor
		"""
		self.OUTGOING_LIFE_SPAN=57.5
		self.INCOMING_LIFE_SPAN=57.5
		self.INTRO_LIFE_SPAN = 27.5
		self.trusted_neighbors = [] #0.5% probability, this list should never be empty, should contain at least one tracker
		self.outgoing_neighbors = [] #49.75% probability
		self.incoming_neighbors = [] #24.825%probability
		self.intro_neighbors= [] #24.825%probability
		self.trusted_neighbors.append(Neighbor(("127.0.0.1",1235),("127.0.0.1",1235),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"130.161.119.206"      , 6421),(u"130.161.119.206"      , 6421),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"130.161.119.206"      , 6422),(u"130.161.119.206"      , 6422),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"131.180.27.155"       , 6423),(u"131.180.27.155"       , 6423),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"83.149.70.6"          , 6424),(u"83.149.70.6"          , 6424),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"95.211.155.142"       , 6427),(u"95.211.155.142"       , 6427),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"95.211.155.131"       , 6428),(u"95.211.155.131"       , 6428),"255,255.255.255"))
		self.trusted_neighbors.append(Neighbor((u"dispersy1.tribler.org", 6421),(u"dispersy1.tribler.org", 6421)))
		self.trusted_neighbors.append(Neighbor((u"dispersy2.tribler.org", 6422),(u"dispersy2.tribler.org", 6422)))
		self.trusted_neighbors.append(Neighbor((u"dispersy3.tribler.org", 6423),(u"dispersy3.tribler.org", 6423)))
		self.trusted_neighbors.append(Neighbor((u"dispersy4.tribler.org", 6424),(u"dispersy4.tribler.org", 6424)))
		self.trusted_neighbors.append(Neighbor((u"dispersy7.tribler.org", 6427),(u"dispersy7.tribler.org", 6427)))
		self.trusted_neighbors.append(Neighbor((u"dispersy8.tribler.org", 6428),(u"dispersy8.tribler.org", 6428)))

	def choose_group(self):
		#return one of the group basing on probability,it is possible to return a empty list
		if(len(self.outgoing_neighbors)==0 and len(self.incoming_neighbors)==0 and len(self.intro_neighbors)==0):
			return ("trusted",self.trusted_neighbors)
		num_random = random.random()*1000
		if(num_random>995):
			return ("trusted",self.trusted_neighbors)
		elif(num_random>497.5):
			return ("outgoing",self.outgoing_neighbors)
		elif(num_random>248.25):
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
		if(neighbor1.get_private_address()==neighbor2.get_private_address() and neighbor1.get_public_address()==neighbor2.get_public_address()):
			return True
		else:
			return False


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

	def add_neighbor_to_outgoing_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.trusted_neighbors) or self.is_in_list(neighbor,self.outgoing_neighbors)):
			self.outgoing_neighbors.append(neighbor)
		print "the outgoing(walk_list) is now:"
		for neighbor in self.outgoing_neighbors:
			print neighbor.get_public_address()


	def add_neighbor_to_incoming_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.trusted_neighbors) or self.is_in_list(neighbor,self.outgoing_neighbors) or self.is_in_list(neighbor,self.incoming_neighbors)):
			self.incoming_neighbors.append(neighbor)
		print "the incoming(stumble_list) is now:"
		for neighbor in self.incoming_neighbors:
			print [neighbor.get_private_address(),neighbor.get_public_address()]


	def add_neighbor_to_intro_list(self,neighbor):
		self.clean_stale_neighbors()
		if not (self.is_in_list(neighbor,self.trusted_neighbors) or self.is_in_list(neighbor,self.outgoing_neighbors) or self.is_in_list(neighbor,self.incoming_neighbors) or self.is_in_list(neighbor,self.intro_neighbors)):
			self.intro_neighbors.append(neighbor)
		print "the intro_list is now:"
		for neighbor in self.intro_neighbors:
			print neighbor.get_public_address()

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
		neighbors_list = self.outgoing_neighbors+self.incoming_neighbors
		if(len(neighbors_list)>0):
			random.shuffle(neighbors_list)
			for n in neighbors_list:
				if(not self.is_same_neighbor(n,neighbor)):
					return n
			return None
		else:
			return None
