Overview of the Code:

Files Changed:
-------------
sr_router.c
sr_utils.c
sr_arpcache.c

Summary:
--------
sr_router.c
The sr_handlepacket function inside sr_router handles all the incoming ARP and ICMP packets. sr_handlepacket sorts the packets into either ARP or ICMP packets and processes the functions seperately.

We followed the logic provided under the tutorial slide to process an ARP and IP packet seperately. For incoming ARP requests, we will send the ARP reply immediately. Otherwise, for all IP packets, we will create the neccessary packet in the logic. Afterwards, we will check if we have the IP resolved in a cache. If it exists, we will encap the packet inside an Ethernet packet and send the packet right away, otherwise, we will cache the packet into an ARP cache and have the ARP sweep function send boardcasts to attempt to resolve the host. Similarly, for ARP replies, we will cache the reply and send all outstanding packets immediately.

sr_utils.c
We added additional utilities functions such as to grab the ip_packet header out of a packet or the find the length of an IP packet. We kept these functions in the sr_utils file to reduce code reduency but also to increase readibility

sr_arpcache.c
We added the sr_arpcache sweep function to send ARP broadcast requests to resolve the MAC addresses for cached ethernet packets.

However, if an ARP request has been sent 5 times, we will send all outstanding packets back to the client and delete the cache.

