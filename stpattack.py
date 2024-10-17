from scapy.all import *
from scapy.layers.l2 import Ether, LLC, Dot1Q
from scapy.packet import Packet
from scapy.fields import ByteField, XShortField, ShortField, MACField

# Extending the standard STP BPDU with the Originating VLAN field
class ExtendedSTP(Packet):
    name = "ExtendedSTP"
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

        # Originating VLAN field added directly into the BPDU (after Bridge Identifier)
        ShortField("originating_vlan", 20)   # Originating VLAN (PVID)
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

# BPDU packet with the Originating VLAN field inside the BPDU structure
bpdu = ExtendedSTP(
   
