import Message
from hashlib import sha256
from struct import pack, unpack_from, calcsize
import os
import sys
if sys.platform == "darwin":
    # Workaround for annoying MacOS Sierra bug: https://bugs.python.org/issue27126
    # As fix, we are using pysqlite2 so we can supply our own version of sqlite3.
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3


class Block(object):
    def init(self,public_key_requester=None,public_key_responder=None,up=None,down=None,total_up_requester=None,total_down_requester=None,
            sequence_number_requester=None,previous_hash_requester=None,signature_requester=None,total_up_responder=None,
            total_down_responder=None,sequence_number_responder=None,previous_hash_responder=None,signature_responder=None):
        self.public_key_requester=public_key_requester
        self.public_key_responder=public_key_responder
        self.up=up
        self.down=down
        self.total_up_requester=total_up_requester
        self.total_down_requester=total_down_requester
        self.sequence_number_requester=sequence_number_requester
        self.previous_hash_requester=previous_hash_requester
        self.signature_requester=signature_requester
        self.total_up_responder=total_up_responder
        self.total_down_responder=total_down_responder
        self.sequence_number_responder=sequence_number_responder
        self.previous_hash_responder=previous_hash_responder
        self.signature_responder=signature_responder

        self.hash_requester=self.encode_block_requester_half()
        self.hash_responder=self.encode_block_crawl()

    def from_payload(self,data):
        """
        data is a tuple (up, down,
                total_up_requester, total_down_requester,
                sequence_number_requester, previous_hash_requester,
                total_up_responder, total_down_responder,
                sequence_number_responder, previous_hash_responder,
                public_key_requester, signature_requester,
                public_key_responder, signature_responder)
        """
        self.up = data[0]
        self.down = data[1]
        self.total_up_requester = data[2]
        self.total_down_requester = data[3]
        self.sequence_number_requester = data[4]
        self.previous_hash_requester = data[5]
        self.total_up_responder = data[6]
        self.total_down_responder = data[7]
        self.sequence_number_responder = data[8]
        self.previous_hash_responder = data[9]
        self.public_key_requester = data[10]
        self.signature_requester = data[11]
        self.public_key_responder = data[12]
        self.signature_responder = data[13]
        self.hash_requester=self.encode_block_requester_half()
        self.hash_responder=self.encode_block_crawl()

    def from_database_record(self,result):
        """
        the result is a tuple (public_key_requester,public_key_responder
                               up,down,total_up_requester,total_down_requester
                               sequence_number_requester,previous_hash_requester,
                               signature_requester,hash_requester,total_up_responder,
                               total_down_responder,sequence_number_responder,
                               previous_hash_responder,signature_responder,hash_responder,
                               insert_time)
        """
        self.public_key_requester = str(result[0])
        self.public_key_responder = str(result[1])
        self.up = int(result[2])
        self.down = int(result[3])
        self.total_up_requester = int(result[4])
        self.total_down_requester = int(result[5])
        self.sequence_number_requester = int(result[6])
        self.previous_hash_requester = str(result[7])
        self.signature_requester = str(result[8])
        self.hash_requester = str(result[9])
        self.total_up_responder = int(result[10])
        self.total_down_responder = int(result[11])
        self.sequence_number_responder = int(result[12])
        self.previous_hash_responder = str(result[13])
        self.signature_responder = str(result[14])
        self.hash_responder = str(result[15])


    def encode_block_requester_half(self):
        return sha256(pack(Message.requester_half_format, *(self.public_key_requester, self.public_key_responder,
                                         self.up, self.down,
                                         self.total_up_requester, self.total_down_requester,
                                         self.sequence_number_requester, self.previous_hash_requester,
                                         self.signature_requester))).digest()

    def encode_block_crawl(self):
        return sha256(pack(Message.crawl_response_format, *(self.up, self.down,
                                         self.total_up_requester, self.total_down_requester,
                                         self.sequence_number_requester, self.previous_hash_requester,
                                         self.total_up_responder, self.total_down_responder,
                                         self.sequence_number_responder, self.previous_hash_responder,
                                         self.public_key_requester, self.signature_requester,
                                         self.public_key_responder, self.signature_responder))).digest()

    def show(self):
        print("total_up_requester is:")
        print self.total_up_requester
        print ("the total_up_responder is:")
        print self.total_up_responder
        print("the public key resquester is:")
        print self.public_key_requester
        print("the public key responder is:")
        print self.public_key_responder

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other): 
        return (self.public_key_requester == other.public_key_requester and
                self.public_key_responder==other.public_key_responder and
                self.up==other.up and
                self.down==other.down and
                self.total_up_requester==other.total_up_requester and
                self.total_down_requester==other.total_down_requester and
                self.sequence_number_requester==other.sequence_number_requester and
                self.previous_hash_requester==other.previous_hash_requester and
                self.signature_requester==other.signature_requester and
                self.total_up_responder==other.total_up_responder and
                self.total_down_responder==other.total_down_responder and
                self.sequence_number_responder==other.sequence_number_responder and
                self.previous_hash_responder==other.previous_hash_responder and
                self.signature_responder==other.signature_responder and
                self.hash_requester==other.hash_requester and
                self.hash_responder==other.hash_responder
                )



class Trusted_Walker_Database:
    def __init__(self):
        self.conn = sqlite3.connect('BlockDataBase.db')
        cursor = self.conn.cursor()
        create_block_table = u"""
                 CREATE TABLE IF NOT EXISTS multi_chain(
                 public_key_requester		TEXT NOT NULL,
                 public_key_responder		TEXT NOT NULL,
                 up                         INTEGER NOT NULL,
                 down                       INTEGER NOT NULL,

                 total_up_requester         UNSIGNED BIG INT NOT NULL,
                 total_down_requester       UNSIGNED BIG INT NOT NULL,
                 sequence_number_requester  INTEGER NOT NULL,
                 previous_hash_requester	TEXT NOT NULL,
                 signature_requester		TEXT NOT NULL,
                 hash_requester		        TEXT PRIMARY KEY,

                 total_up_responder         UNSIGNED BIG INT NOT NULL,
                 total_down_responder       UNSIGNED BIG INT NOT NULL,
                 sequence_number_responder  INTEGER NOT NULL,
                 previous_hash_responder	TEXT NOT NULL,
                 signature_responder		TEXT NOT NULL,
                 hash_responder		        TEXT NOT NULL,

                 insert_time                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                 );
                 """

        create_member_table = u"""
                               CREATE TABLE IF NOT EXISTS member(
                               identity       TEXT,
                               public_key      TEXT
                               )

                               """

        cursor.execute(create_block_table)
        cursor.execute(create_member_table)
        self.conn.commit()
        data = (buffer("block.public_key_requester"), buffer("block.public_key_responder"), 11, 12,
                13, 14,
                15, buffer("block.previous_hash_requester"),
                buffer("block.signature_requester"), buffer("block.hash_requester"),
                16, 17,
                18, buffer("block.previous_hash_responder"),
                buffer("block.signature_responder"), buffer("block.hash_responder"))


    def add_block(self,block):
        script_add_block = u"""
        INSERT INTO multi_chain(public_key_requester,public_key_responder,up,down,
                                total_up_requester,total_down_requester,sequence_number_requester,previous_hash_requester,
                                signature_requester,hash_requester,total_up_responder,total_down_responder,sequence_number_responder,
                                previous_hash_responder,signature_responder,hash_responder
                                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """

        data = (buffer(block.public_key_requester),buffer(block.public_key_responder),block.up,block.down,
                block.total_up_requester,block.total_down_requester,block.sequence_number_requester,buffer(block.previous_hash_requester),
                buffer(block.signature_requester),buffer(block.hash_requester),block.total_up_responder,block.total_down_responder,block.sequence_number_responder,
                buffer(block.previous_hash_responder),buffer(block.signature_responder),buffer(block.hash_responder))
        cursor = self.conn.cursor()
        cursor.execute(script_add_block,data)
        self.conn.commit()

    def get_blocks(self,public_key):
        script_get_blocks = u"""
                            SELECT * from (
                            SELECT * from multi_chain WHERE public_key_requester=? UNION
                            SELECT * from multi_chain WHERE public_key_responder=?)
                            """
        cursor = self.conn.cursor()
        cursor.execute(script_get_blocks,(buffer(public_key),buffer(public_key)))
        self.conn.commit()
        results = cursor.fetchall()
        return results

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

    def get_latest_sequence_number(self, public_key):
        """
        Return the latest sequence number known for this public_key.
        If no block for the pk is know returns -1.
        :param public_key: Corresponding public key
        :return: sequence number (integer) or -1 if no block is known
        """
        public_key = buffer(public_key)
        db_query = u"SELECT MAX(sequence_number) FROM (" \
                   u"SELECT sequence_number_requester AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_requester = ? UNION " \
                   u"SELECT sequence_number_responder AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_responder = ? )"
        cursor = self.conn.cursor()
        cursor.execute(db_query, (public_key, public_key))
        self.conn.commit()
        db_result = cursor.fetchone()[0]
        return db_result if db_result is not None else -1

    def get_all_members(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * from member")
        self.conn.commit()
        members = cursor.fetchall()
        for member in members:
            #print type(member[0])
            print member
    def close(self):
        self.conn.close()


if __name__ == "__main__":
    TW_DB = Trusted_Walker_Database()
    TW_DB.get_all_members()



