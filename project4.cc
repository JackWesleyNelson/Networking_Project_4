//
//  project4.cpp
//  project4
//
//  Created by Phillip Romig on 4/3/12.
//  Copyright 2012 Colorado School of Mines. All rights reserved.
//

//Last edited 12/6/15 by Jack Wesley Nelson

#include "project4.h"

//Define the Ethernet address length
#define ETHERNET_ADDRESS_LENGTH 6
//Define the Ethernet header size
#define ETHERNET_SIZE 14

//Define the Ethernet Header
struct sniff_ethernet{
	//Destination host address
	u_char ether_destination_host[ETHERNET_ADDRESS_LENGTH];
	//Source host address
	u_char ether_source_host[ETHERNET_ADDRESS_LENGTH];
	//Ether type: IP, ARP...
	u_short ether_type;
};

//Define the ARP header
struct sniff_arp{
	//Hardware Type
	u_char arp_hardware_type;
	//Protocol Type
	u_char arp_protocol_type;
	//Hardware Address Length
	u_char arp_hardware_protocol_address_length;
	//Opcode
	u_char arp_opcode;
	//Source hardware address
	u_short arp_source_hardware_address;
	//Source protocol address
	u_short arp_source_protocol_address;
	//Destination hardware address
	u_short arp_destination_hardware_address;
	//Destination protocol address
	u_short arp_destination_protocol_address;
};
//Declare bit fields
#define ARP_PROTOCOL_LENGTH(arp) (((arp)->arp_hardware_protocol_address_length) & 0x0f)
//Hardware length
#define ARP_HARDWARE_LENGTH(arp) (((arp)->arp_hardware_protocol_address_length) >> 4)


//Define the IPv4 header
struct sniff_ipv4{
	//Version header length
	u_char ip_version_header_length;
	//Type of service
	u_char ip_type_of_service;
	//Length
	u_short ip_length;
	//Identification
	u_short ip_identification;
	//Fragment offset
	u_short ip_fragment_offset;
	//Fragment flags
	//Reserved fragment
	#define IP_RESERVED_FRAGMENT 0x8000
	//Don't fragment
	#define IP_DONT_FRAGMENT 0x4000
	//More fragments
	#define IP_MORE_FRAGMENTS 0x2000
	//Fragment Mask
	#define IP_MASK_FRAGMENTS 0x1fff
	//Time to live
	u_char ip_time_to_live;
	//Protocol
	u_char ip_protocol;
	//checksum
	u_short ip_checksum;
	//Source address, Dest address
	struct in_addr ip_source_address,ip_destination_address; 
};
//Declare bit fields
//Header Length
#define IP_HEADER_LENGTH(ip) (((ip)->ip_version_header_length) & 0x0f)
//Version
#define IP_VERSION(ip) (((ip)->ip_version_header_length) >> 4)
#define IP_FLAGS(ip) (((ip)->ip_fragment_offset) >> 3)

#pragma pack(push, 1)
//Define the IPv6 Header
struct sniff_ipv6{
	//Version
	//need 6 bit field for version specified here
	u_char ip_version : 6;
	//Traffic Class
	u_char ip_traffic_class;
	//Flow label
	//need 20 bit field here
	u_int ip_flow_label : 20;
	//Payload length
	u_short ip_payload_length;
	//Next Header
	u_char ip_next_header;
	//Hop limit
	u_char ip_hop_limit;
	//Source Address
	uint64_t ip_source_address_lo;
	int64_t ip_source_address_hi;
	//Destination Address
	uint64_t ip_destination_address_lo;
	int64_t ip_destination_address_hi;
};
#pragma pack(pop)

//Define the TCP header
//definition for the sequence and acknowledgement numbers
typedef u_int tcp_sequence;
//The struct
struct sniff_tcp{
	//Source port
	u_short tcp_source_port;
	//Destination port
	u_short tcp_destination_port;
	//Sequence number
	tcp_sequence tcp_sequence_number;
	//Acknowledgement number
	tcp_sequence tcp_acknowledgement_number;
	//Data offset
	u_char tcp_offsetx2;
	//TCP Offset bit field
	#define TCP_OFF(tcp) (((tcp)->tcp_offsetx2 & 0xf0) >> 4)
	//Flags
	u_char tcp_flags;
	#define TCP_FIN 0x01
	#define TCP_SYN 0x02
	#define TCP_RST 0x04
	#define TCP_PUSH 0x08
	#define TCP_ACK 0x10
	#define TCP_URG 0x20
	#define TCP_ECE 0x40
	#define TCP_CWR 0x80
	#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
	//Window
	u_short tcp_window;
	//Checksum
	u_short tcp_checksum;
	//Urgent Pointer
	u_short tcp_urgent_pointer;
};

//Define the UDP Header
struct sniff_udp{
	//Source port number
	u_short udp_source_port;
	//Destination port number
	u_short udp_destination_port;
	//UDP length
	u_short udp_length;
	//UDP checksum
	u_short udp_checksum;
};


//Define the ICMP header
struct sniff_icmp{
	//ICMP Type
	u_char icmp_type;
	//Type Code
	u_char icmp_type_code;
	//ICMP Checksum
	u_short icmp_checksum;
};



// ****************************************************************************
// * pk_processor()
// *  Most of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every 
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

  resultsC* results = (resultsC*)user;
  results->incrementPacketCount();
  
  // ****************************************************************************
  //  Create structs that we will be using
  //  
  //  
  // ****************************************************************************
  //Ethernet Header struct
  const struct sniff_ethernet *ethernet;
  //ARP Header struct 
  const struct sniff_arp *arp;
  //IPv4 Header struct
  const struct sniff_ipv4 *ipv4;
  //IPv6 Header struct
  const struct sniff_ipv6 *ipv6;
  //TCP Header struct
  const struct sniff_tcp *tcp;
  //UDP Header struct
  const struct sniff_udp *udp;
  //ICMP Header struct
  const struct sniff_icmp *icmp;


  // ****************************************************************************
  //  Time for typecasting and finding out what's in our packet
  //  
  //  
  // ****************************************************************************
  //The ethernet struct is the beginning of our packet, so set the struct here.
  ethernet = (struct sniff_ethernet*)(packet);
  //Change the endianess for comparisons
  u_short type = (ethernet->ether_type >> 8) | (ethernet->ether_type << 8);
  //Add MAC addresses to check unique count
  results->insertMAC(ethernet->ether_destination_host);
  results->insertMAC(ethernet->ether_source_host); 
  //See what values we are dealing with
  //Check if we have an 802.3 frame
  if(type <= 1500){
	results->increment8023Count();	
  }
  //Make sure and increment EthernetII count if needed.
  else if(type > 1500){
	results->incrementEthernetIICount();
  }
  //check if this is IPv4
  if(type == 2048){
  	//The ip field will be after the ethernet, so set the struct after the ethernets size.
	ipv4 = (struct sniff_ipv4*)(packet + ETHERNET_SIZE);
	//Check to see if we have a valid IP Header length
	if((IP_HEADER_LENGTH(ipv4)*4) < 20){
		results->incrementOtherNetworkLayerCount();
	}
	else{
		results->pushBackIPV4((ipv4->ip_length*4));
		results->insertIPV4(inet_ntoa(ipv4->ip_source_address));
		results->insertIPV4(inet_ntoa(ipv4->ip_destination_address));
		if((IP_FLAGS(ipv4) * 4) == 0x2000){
			results->incrementFragmented();
		}
	}
	//Check which structure to use next
	//TCP
	if(ipv4->ip_protocol == 6){
		//The tcp field will be aftr the ethernet and the ip, so set the struct after the ethernet and ip size.
		tcp = (struct sniff_tcp*)(packet + ETHERNET_SIZE + (IP_HEADER_LENGTH(ipv4)*4));
		if((TCP_OFF(tcp)*4) < 20){
			results->incrementOtherTransportLayerCount();
		}
		else{
			results->pushBackTCP((TCP_OFF(tcp)*4));
			results->insertTCP(tcp->tcp_source_port);
			results->insertTCP(tcp->tcp_destination_port);
			if(tcp->tcp_flags == 0x02){
				results->incrementSYN();
			}
			if(tcp->tcp_flags == 0x01){
				results->incrementFIN();
			}
		}
	}
	//UDP
	else if(ipv4->ip_protocol == 17){
		//The udp field will be after the ethernet and the ip, so set the struct after the ethernet and ip size.
		udp = (struct sniff_udp*)(packet + ETHERNET_SIZE + (IP_HEADER_LENGTH(ipv4)*4));
		//check the validity of header length
		if((udp->udp_length*4) < 8){
			results->incrementOtherTransportLayerCount();
		}
		else{
			results->pushBackUDP((udp->udp_length));
			results->insertUDP(udp->udp_source_port);
			results->insertUDP(udp->udp_destination_port);
		}
	}
	//ICMP
	else if(ipv4->ip_protocol == 1){
		//The icmp field will be after the ethernet and the ip, so set the struct after the ethernet and ip size.
		icmp = (struct sniff_icmp*)(packet + ETHERNET_SIZE + (IP_HEADER_LENGTH(ipv4)*4));
		results->pushBackICMP(pkthdr->len);	
	}
	else{
		results->incrementOtherTransportLayerCount();
	}  	
  }
  //Check if thist is ARP
  else if(type == 2054){
	//The arp field will be after the ethernet, so set the struct after the ethernets size.
	arp = (struct sniff_arp*)(packet + ETHERNET_SIZE);
	//Not sure how to check if the arp is valid
	results->pushBackARP(1);
  }
  //Don't really need this, but hey I had the value
  else if(type == 33079){
  }//Check if this is IPv6
  else if(type == 34525){
	//The ip field will be after the ethernet, so set the struct after the ethernets size.
	ipv6 = (struct sniff_ipv6*)(packet + ETHERNET_SIZE);
	//Not sure how to check if the IPv6 is valid...
	results->pushBackIPV6((ipv6->ip_payload_length*4));	
	//Keep track of unique source and destination addresses.
	typedef pair<uint64_t, int64_t> P;
	P source;
	source.first = ipv6->ip_source_address_lo;
	source.second = ipv6->ip_source_address_hi;
	P destination;
	destination.first = ipv6->ip_destination_address_lo;
	destination.second = ipv6->ip_destination_address_hi;
	results->insertIPV6(source);
	results->insertIPV6(destination);

	//Check which structure to use next
	//TCP
	if(ipv6->ip_next_header == 6){
		//The tcp field will be aftr the ethernet and the ip, so set the struct after the ethernet and ip size.
		tcp = (struct sniff_tcp*)(packet + ETHERNET_SIZE + (ipv6->ip_payload_length*4));
		if((TCP_OFF(tcp)*4) < 20){
			results->incrementOtherTransportLayerCount();
		}
		else{
			results->pushBackTCP((TCP_OFF(tcp)*4));
			results->insertTCP(tcp->tcp_source_port);
			results->insertTCP(tcp->tcp_destination_port);
			if(tcp->tcp_flags == 0x02){
				results->incrementSYN();
			}
			if(tcp->tcp_flags == 0x01){
				results->incrementFIN();
			}
		}
	}
	//UDP
	else if(ipv6->ip_next_header == 17){
		//The udp field will be after the ethernet and the ip, so set the struct after the ethernet and ip size.
		udp = (struct sniff_udp*)(packet + ETHERNET_SIZE + (ipv6->ip_payload_length*4));
		//check the validity of header length
		if((udp->udp_length*4) < 8){
			results->incrementOtherTransportLayerCount();
		}
		else{
			results->pushBackUDP((udp->udp_length));
			results->insertUDP(udp->udp_source_port);
			results->insertUDP(udp->udp_destination_port);
		}
	}
	//ICMP
	else if(ipv6->ip_next_header == 1){
		//The icmp field will be after the ethernet and the ip, so set the struct after the ethernet and ip size.
		icmp = (struct sniff_icmp*)(packet + ETHERNET_SIZE + (ipv6->ip_payload_length*4));
		results->pushBackICMP(pkthdr->len);
	
	}
	else{
		results->incrementOtherTransportLayerCount();
	}	
  }
  return;
}


// ****************************************************************************
// * main()
// *  You should not have to worry about anything if you don't want to. 
// *  My code will open the file, initalize the results container class,
// *  call pk_processor() once for each packet and the finally call
// *  the displayResults() method.
// ****************************************************************************
int main (int argc, const char * argv[])
{
  // **********************************************************************
  // * The program is called with a single argument, the name of the
  // * pcap save file to read.
  // **********************************************************************
  if (argc != 2) {
     std::cerr << "usage: project4 <filename>" << std::endl;
     exit(EXIT_FAILURE);
  }


  // **********************************************************************
  // * Instantiate the results class.  
  // **********************************************************************
  resultsC* results = new resultsC();

  // **********************************************************************
  // * Attempt to open the file.
  // **********************************************************************
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *PT;

  bzero(errbuf,PCAP_ERRBUF_SIZE);
  if ((PT = pcap_open_offline(argv[1],errbuf)) == NULL ) {
    std::cerr << "Unable to open pcap file: " << argv[1] << "\n"
         << pcap_geterr(PT) << std::endl;
    exit(EXIT_FAILURE);
  }

  if (strlen(errbuf) > 0)
    std::cerr << "Warning: pcap_open_offline: " << pcap_geterr(PT) << std::endl;



  // **********************************************************************
  // * The dispatcher will call the packet processor once for packet
  // * in the capture file.
  // **********************************************************************
  int pk_count;
  if ((pk_count = pcap_dispatch(PT, -1, pk_processor, (u_char *)results)) < 0) {
    std::cerr << "Error calling dispatcher: " << pcap_geterr(PT) << std::endl;
    exit(EXIT_FAILURE);
  }
  std::cout << "-----------------------Protocol Analyzer----------------------------" << std::endl;

  std::cout << "Dispatcher processed " << pk_count << " packets." << std::endl;


  // **********************************************************************
  // * File your report here.
  // **********************************************************************
  results->displayResults();
  exit(EXIT_SUCCESS);
}


