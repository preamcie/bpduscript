import socket
import struct

def create_pvst_packet(bridge_priority, vlan_id):
    # Ethernet header components
    dst_mac = b'\x01\x00\x0c\xcc\xcc\xcd'  # Destination MAC for Cisco's PVST+
    src_mac = b'\xb4\x45\x06\xae\x38\x96'  # Updated Source MAC as per your input
    eth_type = struct.pack('!H', 0x8100)  # EtherType for VLAN-tagged frame (802.1Q)

    # VLAN Tag
    vlan_prio_cfi_id = struct.pack('!H', (0 << 13) | (0 << 12) | vlan_id)  # CFI: 0, ID: VLAN ID

    # EtherType for SNAP encapsulated LLC
    ether_type_llc_snap = struct.pack('!H', 0x8870)

    # LLC Header
    llc_header = b'\xaa\xaa\x03'  # DSAP, SSAP, Control field

    # SNAP Header
    snap_header = b'\x00\x00\x0c' + struct.pack('!H', 0x010b)  # OUI and PID for PVST+

    # BPDU Data for PVST+
    root_priority_bytes = struct.pack('!H', bridge_priority)
    bridge_priority_bytes = struct.pack('!H', bridge_priority)
    root_identifier = root_priority_bytes + src_mac
    bridge_identifier = bridge_priority_bytes + src_mac

    # BPDU Timers (in 256ths of a second)
    message_age = 1 * 256        # 1 second in 256ths
    max_age = 180 * 256          # 180 seconds (3 minutes) in 256ths
    hello_time = 180 * 256       # 180 seconds (3 minutes) in 256ths
    forward_delay = 15 * 256     # 15 seconds in 256ths (you can adjust this if needed)

    stp_bpdu = (
        b'\x00\x00'  # Protocol Identifier
        + b'\x02'    # Version: Rapid Spanning Tree
        + b'\x02'    # BPDU Type: Rapid/Multiple Spanning Tree
        + b'\x3c'    # BPDU flags: Forwarding, Learning, Port Role: Root (00110100)
        + root_identifier
        + b'\x00\x00\x4e\x20'  # Root Path Cost: 20000
        + bridge_identifier
        + b'\x80\x0b'  # Port Identifier
        + struct.pack('!H', message_age)  # Message Age: 1 second
        + struct.pack('!H', max_age)      # Max Age: 180 seconds (3 minutes)
        + struct.pack('!H', hello_time)   # Hello Time: 180 seconds (3 minutes)
        + struct.pack('!H', forward_delay)  # Forward Delay: 15 seconds
        + b'\x00'      # Version 1 Length
        + b'\x00\x00' + b'\x00\x02' + struct.pack('!H', vlan_id)  # Originating VLAN (PVID) TLV
    )

    # Assemble the full packet
    packet = dst_mac + src_mac + eth_type + vlan_prio_cfi_id + ether_type_llc_snap + llc_header + snap_header + stp_bpdu
    return packet

def send_packet(packet, interface='eth0'):
    # Create a raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    
    # Bind it to the interface
    sock.bind((interface, 0))

    try:
        # Send the packet once
        sock.send(packet)
        print("Packet sent on interface {}".format(interface))
    finally:
        sock.close()

if __name__ == '__main__':
    bridge_priority = int(input("Enter bridge priority (e.g., 24576): "))
    vlan_id = int(input("Enter VLAN ID: "))
    packet = create_pvst_packet(bridge_priority, vlan_id)
    send_packet(packet)  # Using 'eth0' as default
