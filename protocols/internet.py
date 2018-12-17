"""
This class holds an IP-like implementation of packets over UDP sockets.
"""

import hashlib
from socket import socket as Socket
from socket import AF_INET, SOCK_DGRAM
from socket import MSG_PEEK
from typing import Union, Tuple

import construct

from common.exceptions import PayloadTooLarge, SizeMismatch, ChecksumMismatch


MAX_PACKET_SIZE = 512

class Packet:
    """
    This represents an IP-like packet with a checksum.
    """
    HEADER = construct.Struct(
        source_address=construct.Array(4, construct.Byte),
        destination_address=construct.Array(4, construct.Byte),
        packet_length=construct.Short,
        payload_checksum=construct.Bytes(16)
    )

    STRUCTURE = construct.Struct(
        header = HEADER,
        payload = construct.GreedyBytes
    )

    @classmethod
    def build(cls, payload: Union[str, bytes], source, destination) -> bytes:
        if isinstance(payload, str):
            payload = payload.encode()

        if isinstance(source, str):
            source = list(map(int, source.split('.')))

        if isinstance(destination, str):
            destination = list(map(int, destination.split('.')))

        length = len(payload) + cls.HEADER.sizeof()
        if length > MAX_PACKET_SIZE:
            raise PayloadTooLarge

        checksum = hashlib.md5(payload).digest()

        return cls.STRUCTURE.build(
            {'header':
                 {'source_address': source,
                  'destination_address': destination,
                  'packet_length': length,
                  'payload_checksum': checksum},
             'payload': payload}
        )

    @classmethod
    def peek(cls, raw_bytes):
        return cls.STRUCTURE.parse(raw_bytes)

    @classmethod
    def parse(cls, raw_bytes: bytes):
        packet = cls.STRUCTURE.parse(raw_bytes)

        if packet.header.packet_length != len(raw_bytes):
            raise SizeMismatch('Size in header: %d, really %d' %
                               (packet.header.packet_length, len(raw_bytes)))

        if hashlib.md5(packet.payload).digest() != packet.header.payload_checksum:
            raise ChecksumMismatch

        return packet


MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - Packet.HEADER.sizeof()


class Connection:
    def __init__(self, source):
        self.socket = Socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(source)
        self.source = self.socket.getsockname()
        self.source_address, _ = self.source

    def send(self, raw_bytes: bytes, destination: str):
        assert len(raw_bytes) <= MAX_PAYLOAD_SIZE
        packet = Packet.build(raw_bytes, self.source_address, destination[0])
        self.socket.sendto(packet, destination)

    def receive(self) -> Tuple[bytes, Tuple[str, int]]:
        header = Packet.peek(self.socket.recv(Packet.HEADER.sizeof(), MSG_PEEK)).header
        raw_bytes, source = self.socket.recvfrom(header.packet_length)
        return Packet.parse(raw_bytes).payload, source
