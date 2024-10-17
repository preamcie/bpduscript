from scapy.all import *
from scapy.layers.l2 import Ether, LLC, Dot1Q

# Ask for user input on priority and PVID (Port VLAN ID)
user_priority = int(input("Enter the bridge priority (should be a multiple of 4096): "))
pvid = int(input("Enter the PVID (Port VLAN ID): "))  # This is the VLAN ID that will be used as the PVID (originating VLAN)

# Ensure the priority is correctly formatted
priority = user_priority if user_priority % 4096 == 0 else (user_priority // 4096) * 4096

# Interface MAC address
src_mac = get_if_hwaddr("eth0")

# Set destination MAC address for PVST+ BPDUs (Cisco-specific)
dst_mac = "01:00:0C:CC:CC:CD"

# Ethernet frame for STP BPDUs with PVST+ destination MAC
ether = Ether(dst=dst_mac, src=src_mac)

# Correctly handle the PVID (Port VLAN ID) in the 802.1Q header for trunk ports
if pvid == 1:
    # If PVID is 1 (access port), send an untagged BPDU without PVID TLV
    vlan = None  # No VLAN tag for access port (default VLAN 1)
else:
    # For trunk ports, use 802.1Q VLAN tagging with the correct PVID (Port VLAN ID)
    vlan = Dot1Q(vlan=pvid, prio=7, id=0)  # 'prio=7' sets the PCP (Priority Code Point) to 7, DEI is 0

# BPDU packet (STP BPDU with standard fields)
bpdu = STP(
    version=2,  # Version 2 for RSTP (Rapid Spanning Tree)
    bpdutype=0x02,  # 0x02 for Rapid/Multiple Spanning Tree BPDU
    bpduflags=0x3C,  # BPDU flags for Forwarding, Learning, and Designated Port
    rootid=priority,  # Root Bridge priority (does not include PVID)
    rootmac=src_mac,
    pathcost=4,
    bridgeid=priority,  # Bridge ID (does not include PVID directly)
    bridgemac=src_mac,
    portid=0x8001,  # Port ID remains the same
    age=1,
    maxage=20,
    hellotime=2,
    fwddelay=15
)

# Add LLC layer (dsap=0x42, ssap=0x42, ctrl=3)
llc = LLC(dsap=0x42, ssap=0x42, ctrl=3)

# Construct the packet (without the PVID TLV)
if vlan is None:
    # For access port (PVID = 1), send the BPDU without a VLAN tag or PVID TLV
    packet = ether / llc / bpdu
else:
    # For trunk ports, send the BPDU with the VLAN tag
    packet = ether / vlan / llc / bpdu

# Send the packet and print the packet size
try:
    print(f"Sending RSTP BPDU packets without PVID TLV... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
        print(f"Packet size: {len(packet)} bytes")  # Print packet size to verify the default size
except KeyboardInterrupt:
    print("Stopped sending packets.")
