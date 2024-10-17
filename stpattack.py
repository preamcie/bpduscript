from scapy.all import *
from scapy.layers.l2 import Ether, LLC, STP, Dot1Q

# Ask for user input on VLAN ID
vlan_id = int(input("Enter the VLAN ID (use 1 for non-trunk/access port simulation): "))

# Interface MAC address
src_mac = get_if_hwaddr("eth0")

# Ethernet frame for STP BPDUs
ether = Ether(dst="01:80:C2:00:00:00", src=src_mac)

# VLAN tag for trunk port simulation (for non-trunk/access, no VLAN tag will be added)
if vlan_id == 1:
    # For non-trunk (or VLAN 1), do not use VLAN tagging
    vlan = None
else:
    # For trunk ports, use 802.1Q VLAN tagging
    vlan = Dot1Q(vlan=vlan_id)

# STP Configuration BPDU
bpdu = STP(
    version=0,
    bpdutype=0,
    bpduflags=0,
    rootid=32768 + vlan_id,  # Bridge priority (VLAN specific)
    rootmac=src_mac,
    pathcost=4,
    bridgeid=32768 + vlan_id,  # Bridge ID should include the VLAN
    bridgemac=src_mac,
    portid=0x8001,
    age=1,
    maxage=20,
    hellotime=2,
    fwddelay=15
)

# Encapsulate in LLC
llc = LLC(dsap=0x42, ssap=0x42, ctrl=3)

# Construct the packet
if vlan is None:
    # For non-trunk/access port (VLAN 1), no VLAN tag
    packet = ether / llc / bpdu
else:
    # For trunk port (other VLANs), add VLAN tag
    packet = ether / vlan / llc / bpdu

try:
    print("Sending PVST+ BPDU packets... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
except KeyboardInterrupt:
    print("Stopped sending packets.")
