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

//Define the IP header
struct sniff_ip{
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

//Define the TCP header
//definition for the sequence and acknowledgement numbers
typedef u_int tcp_sequence;
//The struct
struct sniff_tcp{
	//Source port
	u_short tcp__source_port;
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
  results->pushBackARP(15);
  results->pushBackARP(17);
  results->pushBackARP(19);

  std:cout << results->getAverageARP();


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
  std::cout << "Dispatcher processed " << pk_count << " packets." << std::endl;


  // **********************************************************************
  // * File your report here.
  // **********************************************************************
  results->displayResults();
  exit(EXIT_SUCCESS);
}


