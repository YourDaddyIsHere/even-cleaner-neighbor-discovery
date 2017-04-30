import sys
sys.path.append("..")
print sys.path
from neighbor_discovery import NeighborDiscover
from nose.tools import assert_equals
from Message import Message
from database import Block
from database import Trusted_Walker_Database
from crypto import ECCrypto
from hashlib import sha1

class Test_Message:
    def setup(self):
        print ("TestUM:setup() before each test method")
        self.crypto = ECCrypto()
        self.my_key1 = self.crypto.generate_key(u"medium")
        self.my_identity1 = self.crypto.key_to_hash(self.my_key1.pub())
        self.my_public_key1 = self.crypto.key_to_bin(self.my_key1.pub())

        self.my_key2 = self.crypto.generate_key(u"medium")
        self.my_identity2 = self.crypto.key_to_hash(self.my_key2.pub())
        self.my_public_key2 = self.crypto.key_to_bin(self.my_key2.pub())
        self.database = Trusted_Walker_Database()
    def teardown(self):
        print ("TestUM:teardown() after each test method")

    @classmethod
    def setup_class(cls):
        print ("setup_class() before any methods in this class")
        #cls.walker = Walker(port=23334)

    @classmethod
    def teardown_class(cls):
        print ("teardown_class() after any methods in this class")

    def test_add_and_get_member(self):
        self.database.add_member(identity=self.my_identity1,public_key=self.my_public_key1)
        result = self.database.get_member(public_key=self.my_public_key1)
        assert str(result[0])==self.my_identity1
        assert str(result[1])==self.my_public_key1

    def test_add_and_get_block(self):

        block1 = Block()
        block1.init(public_key_requester=self.my_public_key1,public_key_responder=self.my_public_key2,up=1,down=2,total_up_requester=3,total_down_requester=4,
                      sequence_number_requester=5,previous_hash_requester="h1",signature_requester="s1",total_up_responder=8,
                      total_down_responder=9,sequence_number_responder=10,previous_hash_responder="h2",signature_responder="s2")

        block2 = Block()
        block2.init(public_key_requester=self.my_public_key2,public_key_responder=self.my_public_key1,up=1,down=2,total_up_requester=3,total_down_requester=4,
                      sequence_number_requester=5,previous_hash_requester="h1",signature_requester="s1",total_up_responder=8,
                      total_down_responder=9,sequence_number_responder=10,previous_hash_responder="h2",signature_responder="s2")
        self.database.add_block(block1)
        self.database.add_block(block2)

        results = self.database.get_blocks(public_key = self.my_public_key1)
        for result in results:
            block = Block()
            block.from_database_record(result = result)
            if block.public_key_requester == self.my_public_key1:
                assert block == block1
            if block.public_key_requester == self.my_public_key2:
                assert block == block2

