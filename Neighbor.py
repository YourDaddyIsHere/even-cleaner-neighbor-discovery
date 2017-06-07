import time
import socket
class Neighbor:
	#wan and lan address should be a tuple (ip,port)
	#outgoing means our device visit this neighbor
	#incoming means this neigbor visits our device
	#private_ip is LAN ip, public_ip is WAN ip
	OUTGOING_LIFE_SPAN=57.5
	INCOMING_LIFE_SPAN=57.5
	INTRO_LIFE_SPAN = 27.5
	last_outgoing_time = 0 
	last_incoming_time = 0
	last_intro_time = 0
	def __init__(self,private_address,public_address,netmask="255.255.255.0",identity=None,public_key=None):
		assert isinstance(private_address,tuple)
		assert isinstance(netmask,str)
		self.private_address = private_address
		self.public_address = public_address
		self.last_outgoing_time = time.time()
		self.last_incoming_time = time.time()
		self.last_intro_time = time.time()
		self.last_trusted_time = time.time()
		self.NETMASK = netmask
		self.identity = identity
		self.public_key = public_key

	def get_private_address(self):
		return self.private_address
	def get_private_ip(self):
		return socket.gethostbyname(self.private_address[0])
	def get_public_ip(self):
		public_ip = socket.gethostbyname(self.public_address[0])
		return public_ip
	def get_public_port(self):
		return self.public_address[1]
	def get_public_address(self):
		return (self.get_public_ip(),self.get_public_port())
