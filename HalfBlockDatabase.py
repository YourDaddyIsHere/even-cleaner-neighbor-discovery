from hashlib import sha256
from struct import pack_into, unpack_from, calcsize

from crypto import ECCrypto
import networkx as nx
import matplotlib.pyplot as plt
#import formats
from hashlib import sha256
from struct import pack, unpack_from, calcsize
import os
import sys
BASE = os.path.dirname(os.path.abspath(__file__))
if sys.platform == "darwin":
    # Workaround for annoying MacOS Sierra bug: https://bugs.python.org/issue27126
    # As fix, we are using pysqlite2 so we can supply our own version of sqlite3.
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3

import logging
from hashlib import sha256

HASH_LENGTH = 32
SIG_LENGTH = 64
PK_LENGTH = 74

GENESIS_HASH = '0'*HASH_LENGTH    # ID of the first block of the chain.
GENESIS_SEQ = 1
UNKNOWN_SEQ = 0
EMPTY_SIG = '0'*SIG_LENGTH
EMPTY_PK = '0'*PK_LENGTH

block_pack_format = "! Q Q Q Q {0}s I {0}s I {1}s {2}s".format(PK_LENGTH, HASH_LENGTH, SIG_LENGTH)
block_pack_size = calcsize(block_pack_format)

#unlike old full-block, this is a halfblock
#HalfBlock contains functions which help you easily convert between Block and Database record
class HalfBlock:
    def __init__(self,database_record=None):
        #create an empty half block instance
        if database_record is None:
            # data
            self.up = self.down = 0
            self.total_up = self.total_down = 0
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            # validation
            self.previous_hash = GENESIS_HASH
            self.signature = EMPTY_SIG
            # debug stuff
            self.insert_time = None
        #create a half block instance basing on a database record
        else:
            (self.up, self.down, self.total_up, self.total_down, self.public_key, self.sequence_number,
             self.link_public_key, self.link_sequence_number, self.previous_hash, self.signature,
             self.insert_time) = (database_record[0], database_record[1], database_record[2], database_record[3], database_record[4], database_record[5], database_record[6], database_record[7], database_record[8],
                                  database_record[9], database_record[10])
            if isinstance(self.public_key, buffer):
                self.public_key = str(self.public_key)
            if isinstance(self.link_public_key, buffer):
                self.link_public_key = str(self.link_public_key)
            if isinstance(self.previous_hash, buffer):
                self.previous_hash = str(self.previous_hash)
            if isinstance(self.signature, buffer):
                self.signature = str(self.signature)

    #pack a block into a tuple which is convenient for database insert
    def pack_db_insert(self):
        """
        Prepare a tuple to use for inserting into the database
        :return: A database insertable tuple
        """
        return (self.up, self.down, self.total_up, self.total_down, buffer(self.public_key), self.sequence_number,
                buffer(self.link_public_key), self.link_sequence_number, buffer(self.previous_hash),
                buffer(self.signature), buffer(self.hash))

    @property
    def hash(self):
        return sha256(self.pack()).digest()

    def pack(self, data=None, offset=0, signature=True):
        """
        Encode this block for transport
        :param data: optionally specify the buffer this block should be packed into
        :param offset: optionally specifies the offset at which the packing should begin
        :param signature: False to pack EMPTY_SIG in the signature location, true to pack the signature field
        :return: the buffer the data was packed into
        """
        buff = data if data else bytearray(block_pack_size)
        pack_into(block_pack_format, buff, offset, self.up, self.down, self.total_up, self.total_down, self.public_key,
                  self.sequence_number, self.link_public_key, self.link_sequence_number, self.previous_hash,
                  self.signature if signature else EMPTY_SIG)
        return str(buff)

    @classmethod
    def unpack(cls, data, offset=0):
        """
        Unpacks a block from a buffer
        :param data: The buffer to unpack from
        :param offset: Optionally, the offset at which to start unpacking
        :return: The MultiChainBlock that was unpacked from the buffer
        """
        ret = HalfBlock()
        (ret.up, ret.down, ret.total_up, ret.total_down, ret.public_key, ret.sequence_number, ret.link_public_key,
         ret.link_sequence_number, ret.previous_hash, ret.signature) = unpack_from(block_pack_format, data, offset)
        return ret

    def sign(self, key):
        """
        Signs this block with the given key
        :param key: the key to sign this block with
        """
        crypto = ECCrypto()
        self.signature = crypto.create_signature(key, self.pack(signature=False))



#a work around with sqlite3 database management tools
#contains functions that help you store/retrieve blocks and Tribler members from database
class HalfBlockDatabase:
    def __init__(self,database_name=os.path.join(BASE, 'BlockDataBase.db'),my_public_key=None):
        self.conn = sqlite3.connect(database_name)
        cursor = self.conn.cursor()
        create_multichain_table = u"""
                CREATE TABLE IF NOT EXISTS multi_chain(
                up                   INTEGER NOT NULL,
                down                 INTEGER NOT NULL,
                total_up             UNSIGNED BIG INT NOT NULL,
                total_down           UNSIGNED BIG INT NOT NULL,
                public_key           TEXT NOT NULL,
                sequence_number      INTEGER NOT NULL,
                link_public_key      TEXT NOT NULL,
                link_sequence_number INTEGER NOT NULL,
                previous_hash          TEXT NOT NULL,
                signature             TEXT NOT NULL,

                insert_time          TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                block_hash	          TEXT NOT NULL,

                PRIMARY KEY (public_key, sequence_number)
                );

                """

        create_member_table = u"""
                               CREATE TABLE IF NOT EXISTS member(
                               identity       TEXT,
                               public_key      TEXT,
                               insert_time          TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                               )

                               """

        create_visit = u"""
                               CREATE TABLE IF NOT EXISTS visit(
                               ip      TEXT,
                               port       INT,
                               public_key      TEXT,
                               insert_time          TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                               )

                               """
        cursor.execute(create_multichain_table)
        cursor.execute(create_member_table)
        cursor.execute(create_visit)
        self.conn.commit()

        blocks = self.get_all_blocks()
        self.my_public_key=my_public_key
        self.trust_graph = TrustGraph(blocks=blocks,my_public_key=my_public_key)

    def add_blocks(self,blocks,commit=True):
        cursor = self.conn.cursor()
        for block in blocks:
            cursor.execute(
            u"INSERT INTO multi_chain (up, down, total_up, total_down, public_key, sequence_number, link_public_key,"
            u"link_sequence_number, previous_hash, signature, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            block.pack_db_insert())
            if commit:
                self.conn.commit()


    def add_block(self,block,commit=True):
        """
        Persist a block
        :param block: The HalfBlock instance that will be saved.
        """
        cursor = self.conn.cursor()
        #only store this block when we not yet have it in database
        if not self.has_block(block):
            cursor.execute(
                u"INSERT INTO multi_chain (up, down, total_up, total_down, public_key, sequence_number, link_public_key,"
                u"link_sequence_number, previous_hash, signature, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                block.pack_db_insert())
            if commit:
                self.conn.commit()
                print("block added, public key:"+block.public_key)
            self.trust_graph.add_block(block)

    def add_member(self,identity,public_key):
        script_add_member = u"INSERT INTO member (identity,public_key) VALUES(?,?)"
        data = (buffer(identity),buffer(public_key))
        print("the buffered public_key is:")
        print(public_key)
        cursor = self.conn.cursor()
        cursor.execute(script_add_member,data)
        self.conn.commit()


    def get_member(self,identity=None,public_key=None):
        cursor = self.conn.cursor()
        if not (identity or public_key):
            return None
        if identity:
            cursor.execute("SELECT * from member where identity=?",(buffer(identity),))
            self.conn.commit()
            member = cursor.fetchone()
            print type(member)
            print member
            return member
        if public_key:
            cursor.execute("SELECT * from member where public_key=?",(buffer(public_key),))
            self.conn.commit()
            member = cursor.fetchone()
            print type(member)
            print member
            return member

    def get_all_member(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * from member")
        self.conn.commit()
        result = cursor.fetchone()
        member = (str(result[0]),str(result[1]))
        return member


    def get_latest_sequence_number(self, public_key):
        """
        Return the latest sequence number known for this public_key.
        If no block for the pk is know returns -1.
        :param public_key: Corresponding public key
        :return: sequence number (integer) or -1 if no block is known
        """
        public_key = buffer(public_key)
        db_query = u"""
                    SELECT MAX(sequence_number) FROM multi_chain WHERE public_key = ?
                    """
        cursor = self.conn.cursor()
        cursor.execute(db_query,(buffer(public_key), ))
        self.conn.commit()
        db_result = cursor.fetchone()[0]
        print("the latest sequence number is:"+str(db_result))
        return db_result if db_result is not None else 0

    def get_blocks_since(self,public_key,sequence_number):
        db_query = "SELECT * FROM multi_chain WHERE sequence_number >= ? AND public_key = ?"
        cursor = self.conn.cursor()
        print("the type of db query is:")
        print(type(db_query))
        print("the type of sequence number is:")
        print(type(sequence_number))
        print("get blocks of public key: ")
        print(type(public_key))
        print repr(public_key)
        sequence_number_int = int(sequence_number)
        public_key_buffer = buffer(public_key)
        cursor.execute(db_query,(sequence_number_int,public_key_buffer))
        self.conn.commit()
        db_results = cursor.fetchall()
        blocks=[]
        for db_result in db_results:
            block = HalfBlock(database_record=db_result)
            blocks.append(block)
        return blocks


    def get_blocks_by_public_key(self,public_key):
        script_get_blocks = u"""
                            SELECT * from multi_chain WHERE public_key=? 
                            """
        cursor = self.conn.cursor()
        cursor.execute(script_get_blocks,(buffer(public_key),))
        self.conn.commit()
        results = cursor.fetchall()
        return results

    def get_all_blocks(self):
        script_get_all =u"""
                         SELECT * from multi_chain
                         """
        cursor = self.conn.cursor()
        cursor.execute(script_get_all)
        self.conn.commit()
        db_results = cursor.fetchall()
        blocks=[]
        for db_result in db_results:
            block = HalfBlock(database_record=db_result)
            blocks.append(block)
        return blocks



    def has_block(self,block):
        script = u"""
                 SELECT * from multi_chain WHERE public_key=? AND sequence_number=?
                  """
        cursor = self.conn.cursor()
        cursor.execute(script,(buffer(block.public_key),block.sequence_number))
        self.conn.commit()
        result = cursor.fetchone()
        if result:
            return True
        else:
            return False

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

    def add_visit_record(self,ip,port,public_key):
        script_insert = u"""
                         INSERT into visit(ip,port,public_key) VALUES(?,?,?)
                         """
        cursor = self.conn.cursor()
        cursor.execute(script_insert,(buffer(ip),port,buffer(public_key)))
        self.conn.commit()

    def get_all_visit_records(self):
        script_query = u"""
                         SELECT * from visit ORDER BY insert_time ASC
                         """
        cursor = self.conn.cursor()
        cursor.execute(script_query)
        self.conn.commit()
        results = cursor.fetchall()
        return results





class TrustGraph():
    def __init__(self,blocks=[],is_halfblock=True,my_public_key=None):
        self.is_halfblock = is_halfblock
        self.Graph = nx.DiGraph()
        self.edges_list = []
        self.nodes_list = []
        self.my_public_key=my_public_key
        for block in blocks:
            self.add_block(block)

    """
    add a new block
    if the corresponding edge exists, update the 'weight' attribute
    if the corresponding edge doesn't exist
    add that edge and corresponding node
    """


    def add_block(self,block):
        #when we use old block protocol
        #should we still support old protocol?
        """
        if self.is_halfblock == False:
        
            if self.Graph.has_edge(block.public_key_requester,block.public_key_responder):
               self.Graph[block.public_key_requester][block.public_key_responder]["weight"] = self.Graph[block.public_key_requester][block.public_key_responder]["weight"] + block.up
            else:
                self.Graph.add_edge(block.public_key_requester,block.public_key_responder,weight=block.up)
                self.edges_list.append((block.public_key_requester,block.public_key_responder))
                if not block.public_key_requester in self.nodes_list:
                    self.nodes_list.append(block.public_key_requester)
                if not block.public_key_responder in self.nodes_list:
                    self.nodes_list.append(block.public_key_responder)

            if self.Graph.has_edge(block.public_key_responder,block.public_key_requester):
                self.Graph[block.public_key_responder][block.public_key_requester]["weight"] +=block.down
            else:
                self.Graph.add_edge(block.public_key_responder,block.public_key_requester,weight=block.up)
                self.edges_list.append((block.public_key_responder,block.public_key_requester))
                if not block.public_key_requester in self.nodes_list:
                    self.nodes_list.append(block.public_key_requester)
                if not block.public_key_responder in self.nodes_list:
                    self.nodes_list.append(block.public_key_responder)
        """
        #when we want to store a Half Block
        if self.is_halfblock == True:
            if self.Graph.has_edge(block.public_key,block.link_public_key):
               self.Graph[block.public_key][block.link_public_key]["weight"] = self.Graph[block.public_key][block.link_public_key]["weight"] + block.up
            else:
                self.Graph.add_edge(block.public_key,block.link_public_key,weight=block.up)
                self.edges_list.append((block.public_key,block.link_public_key))
                if not block.public_key in self.nodes_list:
                    self.nodes_list.append(block.public_key)
                if not block.link_public_key in self.nodes_list:
                    self.nodes_list.append(block.link_public_key)

            if self.Graph.has_edge(block.link_public_key,block.public_key):
                self.Graph[block.link_public_key][block.public_key]["weight"] +=block.down
            else:
                self.Graph.add_edge(block.link_public_key,block.public_key,weight=block.up)
                self.edges_list.append((block.link_public_key,block.public_key))
                if not block.public_key in self.nodes_list:
                    self.nodes_list.append(block.public_key)
                if not block.link_public_key in self.nodes_list:
                    self.nodes_list.append(block.link_public_key)


    def has_trust_path(self,your_node,node_to_be_trusted):
        """
        A trust B if and only if there is a directed path from B to A
        :param your_node:the public key of yours
        :param node_to_be_trusted: the public key that you want to check "do I have trust path with him"
        """
        if self.Graph.has_node(your_node) and self.Graph.has_node(node_to_be_trusted) and nx.has_path(self.Graph,source=node_to_be_trusted,target=your_node):
            return True
        else:
            return False


    def draw_graph(self):
        #draw a trust graph using matplotlib
        pos = nx.shell_layout(self.Graph)

        nx.draw_networkx_nodes(self.Graph,pos,
                       nodelist=self.nodes_list,
                       node_color='r',
                       node_size=20,
                       alpha=0.8)


        nx.draw_networkx_edges(self.Graph,pos,
                       edgelist=self.edges_list,
                       width=1,alpha=0.2,edge_color='r')

        if self.my_public_key:
            self.my_node = self.my_public_key
            self.trusted_node =[]
            self.trusted_edge = []

            for node in self.nodes_list:
                if self.has_trust_path(your_node=self.my_node,node_to_be_trusted=node) == True:
                    self.trusted_node.append(node)
            for node1 in self.trusted_node:
                for node2 in self.trusted_node:
                    if node1 !=node2 and self.Graph.has_edge(node1,node2):
                        self.trusted_edge.append((node1,node2))


            nx.draw_networkx_nodes(self.Graph,pos,
                           nodelist=self.trusted_node,
                           node_color='g',
                           node_size=20,
                           alpha=0.8)
            """
            nx.draw_networkx_nodes(self.Graph,pos,
                           nodelist=[self.my_node],
                           node_color='b',
                           node_size=20,
                           alpha=0.8)
            """

            nx.draw_networkx_edges(self.Graph,pos,
                           edgelist=self.trusted_edge,
                           width=1,alpha=0.2,edge_color='g')

        #plt.show()