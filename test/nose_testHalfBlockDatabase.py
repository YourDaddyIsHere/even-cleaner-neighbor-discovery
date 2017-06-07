import sys
import os
sys.path.append("..")
print sys.path
from neighbor_discovery import NeighborDiscover
from nose.tools import assert_equals
from Message import Message
from HalfBlockDatabase import HalfBlock,HalfBlockDatabase
from crypto import ECCrypto
from hashlib import sha1
import logging

logging.basicConfig(level=logging.DEBUG, filename="logfile", filemode="a+",format="%(asctime)-15s %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class Test_Message:
    def setup(self):
        print ("TestUM:setup() before each test method")
        self.crypto = ECCrypto()
        self.my_key1 = self.crypto.generate_key(u"medium")
        self.my_key2 = self.crypto.generate_key(u"medium")
        self.my_key3 = self.crypto.generate_key(u"medium")
        self.my_key4 = self.crypto.generate_key(u"medium")
        self.my_key5 = self.crypto.generate_key(u"medium")
        self.my_identity1 = self.crypto.key_to_hash(self.my_key1.pub())
        self.my_identity2 = self.crypto.key_to_hash(self.my_key2.pub())
        self.my_identity3 = self.crypto.key_to_hash(self.my_key3.pub())
        self.my_identity4 = self.crypto.key_to_hash(self.my_key4.pub())
        self.my_identity5 = self.crypto.key_to_hash(self.my_key5.pub())
        self.my_public_key1 = self.crypto.key_to_bin(self.my_key1.pub())
        self.my_public_key2 = self.crypto.key_to_bin(self.my_key2.pub())
        self.my_public_key3 = self.crypto.key_to_bin(self.my_key3.pub())
        self.my_public_key4 = self.crypto.key_to_bin(self.my_key4.pub())
        self.my_public_key5 = self.crypto.key_to_bin(self.my_key5.pub())
        if os.path.isfile('BlockDataBase.db'):
            os.remove('BlockDataBase.db')
        self.database = HalfBlockDatabase()
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

        block1 = HalfBlock()
        block1.public_key = self.my_public_key1

        block2 = HalfBlock()
        block2.public_key = self.my_public_key2
        self.database.add_block(block1)
        self.database.add_block(block2)

        results = self.database.get_blocks_by_public_key(public_key = self.my_public_key1)
        for result in results:
            block = HalfBlock(result)
            if block.public_key == self.my_public_key1:
                block.insert_time=block1.insert_time
                assert block.insert_time == block1.insert_time
            if block.public_key == self.my_public_key2:
                block.insert_time=block2.insert_time
                assert block == block2
    def test_has_block(self):
        block3 = HalfBlock()
        block3.public_key = self.my_public_key3

        block4 = HalfBlock()
        block4.public_key = self.my_public_key4
        self.database.add_block(block3)
        status1 = self.database.has_block(block3)
        status2 = self.database.has_block(block4)

        assert status1 == True
        assert status2 == False
