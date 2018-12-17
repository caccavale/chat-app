"""
This holds a TCP-lite-like implementation for transferring ordered information over
and unordered protocol.  More error handling should have been done, as indicated by
several #TODOs where RST (resets) could have been initiated.
"""

import threading

from dataclasses import dataclass

import construct

from common.exceptions import PayloadTooLarge
from protocols.internet import MAX_PAYLOAD_SIZE as MAX_PACKET_SIZE
from protocols.internet import Connection as IPConnection

class ResetNeeded(Exception):
    pass

@dataclass
class Packet:
    """
    This is a TCP-lite-like packet.
    """
    source_port: int = None
    destination_port: int = None
    sequence_number: int = None
    acknowledgment_number: int = None
    syn: bool = 0
    ack: bool = 0
    psh: bool = 0
    rst: bool = 0
    payload: bytes = None

    def __post_init__(self):
        if isinstance(self.payload, str):
            self.payload = self.payload.encode()

        if len(self.payload) + self.HEADER.sizeof() > MAX_PACKET_SIZE:
            raise PayloadTooLarge

    HEADER = construct.Struct(
        source_port=construct.Short,
        destination_port=construct.Short,
        sequence_number=construct.Int,
        acknowledgment_number=construct.Int,
        flags = construct.BitStruct(
            ack=construct.Bit,
            psh=construct.Bit,
            rst=construct.Bit,
            _=construct.Padding(5)
        )
    )

    STRUCTURE = construct.Struct(
        header = HEADER,
        payload = construct.GreedyBytes
    )

    def build(self) -> bytes:
        #print(self)
        return self.STRUCTURE.build({
            'header':
                {'source_port': self.source_port,
                 'destination_port': self.destination_port,
                 'sequence_number': self.sequence_number,
                 'acknowledgment_number': self.acknowledgment_number,
                 'flags':
                    {
                     'ack': self.ack,
                     'psh': self.psh,
                     'rst': self.rst
                    }
                },
            'payload': self.payload
        })

    @classmethod
    def parse(cls, raw_bytes: bytes) -> 'Packet':
        packet = cls.STRUCTURE.parse(raw_bytes)

        return packet


MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - Packet.HEADER.sizeof()

class Connection:
    """
    This defines a TCP-lite-like connection with _one_ other.
    """
    def __init__(self, source, destination, multiplexer,
                 sequence_number: int = 0,
                 acknowledgment_number: int = 0):

        self.source = source
        self.source_address, self.source_port = self.source

        self.destination = destination
        self.destination_address, self.destination_port = self.destination

        self.multiplexer = multiplexer

        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number

        self.inbound_packets = []
        self.outbound_packets = []

    def receive(self, payload: bytes):
        packet = Packet.parse(payload)
        if packet.header.flags.ack:
            if packet.header.acknowledgment_number != self.sequence_number:
                pass # TODO RST
            elif self.outbound_packets:
                self.push_one_outbound_packet()
            return
        else:
            if len(self.inbound_packets) == 0:
                pass # This is the first of potentially several packets

            if packet.header.flags.rst:
                pass  # TODO HANDLE THIS

            if packet.header.sequence_number != self.acknowledgment_number:
                pass  # TODO SEND RST

            self.acknowledgment_number += len(packet.payload)
            self.inbound_packets.append(packet)

            ack = Packet(self.source_port,
                         self.destination_port,
                         self.sequence_number,
                         self.acknowledgment_number,
                         payload = b'')
            ack.ack = 1
            self.multiplexer._send_raw(ack.build(), self.destination)

            if packet.header.flags.psh:
                self.multiplexer.message_received_callback(
                    b''.join([packet.payload for packet in self.inbound_packets]),
                    self.destination
                )
                self.inbound_packets = []

    def send(self, payload):
        chunks = [payload[i:i + MAX_PAYLOAD_SIZE] for i in
                  range(0, len(payload), MAX_PAYLOAD_SIZE)]

        packets = [Packet(self.source_port,
                          self.destination_port,
                          self.sequence_number,
                          self.acknowledgment_number,
                          payload=chunk) for chunk in chunks]

        packets[-1].psh = 1

        self.outbound_packets += packets
        self.push_one_outbound_packet()

    def push_one_outbound_packet(self):
        packet = self.outbound_packets.pop(0)
        self.multiplexer._send_raw(packet.build(), self.destination)
        self.sequence_number += len(packet.payload)


class Multiplexer(threading.Thread):
    """
    This multiplexes all packets over self.connection to respective Connections.
    """
    def __init__(self, source, message_received_callback):
        if source is None:
            source = ('', 0)
        self.connection = IPConnection(source)
        self.source = self.connection.source

        self.message_received_callback = message_received_callback
        self.connections = {}

        super().__init__(target=self)
        self.start()

    def run(self):
        try:
            while True:
                self.receive()
        except KeyboardInterrupt:
            self.connection.socket.close()
            exit(0)

    def receive(self):
        payload, source = self.connection.receive()
        if source not in self.connections:
            self.connections[source] = Connection(self.source, source, self)
        self.connections[source].receive(payload)

    def send(self, payload, destination):
        if destination not in self.connections:
            self.connections[destination] = Connection(self.source, destination, self)
        self.connections[destination].send(payload)

    def _send_raw(self, payload, destination):
        self.connection.send(payload, destination)
