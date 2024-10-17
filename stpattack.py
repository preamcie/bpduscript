from scapy.all import *
from scapy.layers.l2 import Ether, LLC, Dot1Q
from scapy.fields import XShortField, ShortField

# Define the PVID TLV (Type-Length-Value) that will be appended to the BPDU
class PVID_TLV(Packet):
    fields_desc = [
        XShortField("type", 0x0000),      # Type: PVID (0x0000)
        ShortField("length", 2),          # Length: 2 bytes
        ShortField("vlan_id", 0)          # The VLAN ID (PVID)
    ]

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

# For trunk ports, append the PVID TLV after the BPDU
if vlan is None:
    # For access port (PVID = 1), send the BPDU without a VLAN tag or PVID TLV
    packet = ether / llc / bpdu
else:
    # Create the PVID TLV to append at the end of the BPDU for trunk ports
    pvid_tlv = PVID_TLV(vlan_id=pvid)
    # Manually append the BPDU and the PVID TLV to make sure they are combined properly
    packet = ether / vlan / llc / bpdu / Raw(pvid_tlv)

# Send the packet and print the packet size
try:
    print(f"Sending RSTP BPDU packets with PVID TLV (VLAN {pvid})... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
        print(f"Packet size: {len(packet)} bytes")  # Print packet size to verify 68 bytes
except KeyboardInterrupt:
    print("Stopped sending packets.")
