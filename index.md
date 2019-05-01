# Overview

The basic function of an XDP program involves packet inspection, analysis and modification. This post provides a precise description of the basic data structures and functions involved in an XDP program.


## Return Enum

After a packet is handled by the XDP Program, it has to continue with either of the following operations,

**1. Abort:** Abort the execution of an XDP Program. The current and future incoming packets in the interface are not processed by XDP. This is a non-graceful exit. 

**2. Drop:** Drop the packet from the interface. 

**3. Pass:** Pass the packet to the kernel stack to reach the application. 

**4. Transmit:** Emit the packet to the same interface it arrived at. 

**5. Redirect:** Redirect into a BPF cpumap, meaning, the CPUs serving XDP on the NIC’s receive queues can continue to do so and push the packet for processing the upper kernel stack to a remote CPU. 

```
/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```
Source: `/include/uapi/linux/bpf.h`

## Incoming packet

Every incoming packet in a XDP program resides in an `xdp_md` data structure.

```
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};
```
Source: `/include/uapi/linux/bpf.h`

## Ethernet packet

The incoming packet is an ethernet packet and can be cast to `ethhdr` to access the header fields.

```
SEC("ethr_example")
int ethr_example(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
  
  return XDP_PASS;
}
```

Before analysing the ethernet header, verfication is required to check whether `data_end` is out of bounds compared to the ethernet packet

 ```
 nh_off = sizeof(*eth);
	if(data + nh_off > data_end)
		return XDP_DROP;
 ```
 
The fields of an ethernet packet can be used for analysis and modification.

```
/*
 *	This is an Ethernet frame header.
 */

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));
```
Source: `/include/uapi/linux/if_ether.h`

An example of ethernet packet inspection is as follows. The below example checks for the underlying network layer protocol. The function `htons` converts an integer from host level to network level byte order.

```
h_proto = eth->h_proto;


	if (h_proto == htons(ETH_P_IP))
		// Handling of IPv4 packet
	else if (h_proto == htons(ETH_P_IPV6))
		// Handling of IPv6 packet
```

## IP Packet

The encapsulated IP packet can be retrieved from the ethernet packet as follows
```
struct iphdr *iph = data + sizeof(struct ethhdr);
```

Verfication is again required.
```
if (iph + 1 > data_end)
		return XDP_DROP;
```

The fields of an IP packet can be used for analysis and modification. 

### IPv4 Header:

```
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};
```
Source: `/include/uapi/linux/ip.h`

### IPv6 Header:

```
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};
```
Source: `/include/uapi/linux/ipv6.h`

## Transport Layer Packet

The IP protocol header field can be used to determined if the packet is TCP or UDP. The transport header can be retreived as follows. The `data_end` bound verification is also required.

```
	struct tcphdr *th;
	struct udphdr *uh;
  
  switch (iph->protocol) // iph->protocol if packet is IPv4 or iph->nexthdr if packet is IPv6
  {
	case IPPROTO_TCP:
		th = (struct tcphdr *)(iph + 1);
		if (th + 1 > data_end)
			return XDP_DROP;
		// Handle TCP Packet
	case IPPROTO_UDP:
		uh = (struct udphdr *)(iph + 1);
		if (uh + 1 > data_end)
			return XDP_DROP;
		// Handle UDP Packet
	default:
		return XDP_DROP;
	}
```

The following describes the `tcphdr` and `udphdr` structures. 

### TCP Header:

```
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
```
Source: `/include/uapi/linux/tcp.h`

### UDP Header:

```
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};
```
Source: `/include/uapi/linux/udp.h`

## Concerns for retrieving and modifying packets

### Byte order translation

Integers retrieved from packets must be converted to host order byte order using `ntohs` or `ntohl` depending on the data size. 

```
// If the destination port of the packet is 5001, 
// it will be stored in the packet as htons(5001) = 35091

dest_port = ntohs(th->dest);
```

Similarly, before changing packet contents, the integer must be converted to network byte order using `htons` or `htonl` depending on the data size.


```
// If we have to change the destination port to 8000, 
// we need to convert it to network byte order first

th->dest = htons(8000);
```

### Incorrect checksum

Modifying packet headers results in incorrect checksum which makes in interface drop the packet. To prevent this,

1. Disable checksum - security risk

2. Recalculate checksum - The L4 checksum can be re calculated and assigned by `bpf_l4_csum_replace` function defined in `/net/core/filter.c`. There exists functions to re calculate other checksum differences as well. Currently, this function has _not_ been tested. This solution is just a suggestion based on reserach about modifying L4 checksum on XDP (which might not be extensive or enough).


