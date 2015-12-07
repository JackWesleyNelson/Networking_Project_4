//
//  resultsC.cc
//  project4
//
//  Created by Phillip Romig on 4/3/12.
//  Copyright 2012 Colorado School of Mines. All rights reserved.
//

//Last edited 12/6/15 by Jack Wesley Nelson

#include "project4.h"

// ***************************************************************************
// * resultsC::resultsC
// *  Constructor for the results container class.  
// ***************************************************************************
resultsC::resultsC() {
  totalPacketCount = 0;
  numberEthernetII = 0;
  number8023 = 0;
  numberOtherNetworkLayer = 0;
  numberOtherTransportLayer = 0;
  numberSYN = 0;
  numberFIN = 0;
  numberFragmented = 0;
}


// ***************************************************************************
// * displayResults:
// *  This method will be called once, after all the packets have been
// *  processed.  You should use this to print all the statistics you
// *  collected to stdout.
// ***************************************************************************
void resultsC::displayResults() {

  std::cout << "A total of " << totalPacketCount << " packets processed." << std::endl;

  std::cout << "--------------------------Link Layer--------------------------------" << std::endl;

  std::cout << "A total of " << numberEthernetII << " Ethernet II frames." << std::endl;

  std::cout << "A total of " << number8023 << " 802.3 frames." << std::endl;

  std::cout << "-------------------------Network Layer------------------------------" << std::endl;

  std::cout << "A total of " << getCountARP() << " ARP packets. (Average, Maximum, Minimum) Size: (" << getAverageARP() << ", " << getMaximumARP() << ", " << getMinimumARP() << ")." << std::endl;

  std::cout << "A total of " << getCountIPV4() << " IPv4 packets. (Average, Maximum, Minimum) Size: (" << getAverageIPV4() << ", " << getMaximumIPV4() << ", " << getMinimumIPV4() << ")." << std::endl;

  std::cout << "A total of " << getCountIPV6() << " IPv6 packets. (Average, Maximum, Minimum) Size: (" << getAverageIPV6() << ", " << getMaximumIPV6() << ", " << getMinimumIPV6() << ")." << std::endl;

  std::cout << "A total of " << numberOtherNetworkLayer << " unrecognized packets." << std::endl;

  std::cout << "------------------------Transport Layer-----------------------------" << std::endl;

  std::cout << "A total of " << getCountICMP() << " ICMP packets. (Average, Maximum, Minimum) Size: (" << getAverageICMP() << ", " << getMaximumICMP() << ", " << getMinimumICMP() << ")." << std::endl;

  std::cout << "A total of " << getCountTCP() << " TCP packets. (Average, Maximum, Minimum) Size: (" << getAverageTCP() << ", " << getMaximumTCP() << ", " << getMinimumTCP() << ")." << std::endl;

  std::cout << "A total of " << getCountUDP() << " UDP packets. (Average, Maximum, Minimum) Size: (" << getAverageUDP() << ", " << getMaximumUDP() << ", " << getMinimumUDP() << ")." << std::endl;

  std::cout << "A total of " << numberOtherTransportLayer << " unrecognized packets." << std::endl;

  std::cout << "-----------------------Protocol Details------------------------------" << std::endl;

  std::cout << "A total of " << getCountUniqueMAC() << " Unique source/destination MAC addresses." << std::endl;
  std::cout << "A total of " << getCountUniqueIPV4() << " Unique source/destination IPV4 addresses." << std::endl;
  std::cout << "A total of " << getCountUniqueIPV6() << " Unique source/destination IPV6 addresses." << std::endl;
  std::cout << "A total of " << getCountUniqueUDP() << " Unique source/destination UDP ports." << std::endl;
  std::cout << "A total of " << getCountUniqueTCP() << " Unique source/destination TCP ports." << std::endl;
  std::cout << "A total of " << numberSYN << " TCP SYN packets seen." << std::endl;
  std::cout << "A total of " << numberFIN << " TCP FIN packets seen." << std::endl;
  std::cout << "A total of " << numberFragmented << " fragmented IP packets seen. " << std::endl;

  std::cout << "---------------------------------------------------------------------" << std::endl << std::endl;







}
