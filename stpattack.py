from scapy.all import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet
from scapy.fields import ByteField, XShortField, MACField, ShortField

# Custom STP packet structure to include an Originating VLAN field
class CustomSTP(Packet):
    name = "CustomSTP"
    fields_desc = [
        ByteField("protocol_id", 0),         # Protocol Identifier (STP uses 0)
        ByteField("version", 2),             # Protocol Version (RSTP uses 2)
        ByteField("bpdutype", 0x02),         # BPDU Type (0x02 for Rapid Spanning Tree)
        ByteField("bpduflags", 0x3C),        # BPDU Flags (0x3C for Forwarding, Learning, Designated Port Role)
        XShortField("rootid", 0),            # Root Bridge Identifier (Bridge Priority + System ID Extension)
        MACField("rootmac", "00:00:00:00:00:00"),  # Root Bridge MAC Address
        XShortField("pathcost", 0),          # Path Cost to the Root Bridge
        XShortField("bridgeid", 0),          # Bridge Identifier (Bridge Priority + System ID Extension)
        MACField("bridgemac", "00:00:00:00:00:00"),  # Bridge MAC Address
        ShortField("portid", 0x8001),        # Port Identifier
        ByteField("age", 1),                 # Message Age
        ByteField("maxage", 20),             # Maximum Age
        ByteField("hellotime", 2),           # Hello Time
        ByteField("fwddelay", 15),           # Forward Delay
        XShortField("originating_vlan", 1)   # Custom Originating VLAN field (PVID)
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
    # If PVID is 1 (access port), send an untagged BPDU
    vlan = None  # No VLAN tag for access port (default VLAN 1)
else:
    # For trunk ports, use 802.1Q VLAN tagging with the correct PVID (Port VLAN ID)
    vlan = Dot1Q(vlan=pvid, prio=7, id=0)  # 'prio=7' sets the PCP (Priority Code Point) to 7, DEI is 0

# Construct custom BPDU with Originating VLAN field
bpdu = CustomSTP(
    protocol_id=0,
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
    fwddelay=15,
    originating_vlan=pvid  # Custom field for the originating VLAN
)

# Construct the packet (without LLC)
if vlan is None:
    # For access port (PVID = 1), send the BPDU without a VLAN tag
    packet = ether / bpdu
else:
    # For trunk port (PVID other than 1), send the BPDU with the PVID in the 802.1Q tag
    packet = ether / vlan / bpdu

try:
    print(f"Sending RSTP BPDU packets with Originating VLAN {pvid} and BPDU Flags 0x3C... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
except KeyboardInterrupt:
    print("Stopped sending packets.")
