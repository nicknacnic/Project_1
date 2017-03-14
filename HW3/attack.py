import requests
import dpkt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import os
import time
import fcntl, socket, struct

def inject_pkt(pkt):
    import dnet
    dnet.ip().send(pkt)

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

print (getHwAddr('eth0'))

#if 'http://freeaeskey.xyz/' in request.GET:
    # replace the key provided with the key: 49276d20737475636b20696e20616e20414553206b657920666163746f727921
