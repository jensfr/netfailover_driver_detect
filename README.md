# network failover driver behaviour detection
Some NIC drivers will update the MAC filter as soon as  a vf is created,
but before the vf driver is loaded in the guest and the vf device is ready.
Therefore packets are not going to the standby(virtio) device but to the pf until
the guest is up and the vf driver is loaded.

A more detailed description of the net failover feature and open problems is [here](https://www.linux-kvm.org/index.php?title=Failover)

This provides two simple tools. One, send_packet will send a series of packets to
the MAC address of the device to be tested with a special payload that can be given as a
command line parameter. The goal is to see if the packet(s) will go to
the pf device or vf device. 

The second tool is_legacy is started on the target system and pointed to the device we want
to sniff packets from. It will return 0 if the packet with special payload was received on this device and
1 if no such packet was detected. 

## How to use it
### Build
Clone this repository. Run 'make'.

### Run
From source system run ./send_packet -d <dev> 
  
On target system. First try sniffing on pf device with ./is_legacy -d <pf-dev>. If is_legacy returns 0 it means it has received the packets
sent by send_packet. If it returns 1 it didn't receive the packet. Now run ./is_legacy  -d <vf-dev>. 
  
If the packet is received on the vf device
it means that the driver is behaving in above described way, setting up the MAC filter too early, directing packets to the vf before
guest is up and ready to receive packets. 
