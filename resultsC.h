//
//  resultsC.h
//  Project4
//
//  Created by Phillip Romig on 4/3/12.
//  Copyright 2012 Colorado School of Mines. All rights reserved.
//

//Last edited 12/6/15 by Jack Wesley Nelson

#ifndef resultsC_h
#define resultsC_h

#include <vector>

using namespace std;

class resultsC {
  protected:
   //Total packet count
   int totalPacketCount;
   //Link layer counts
   int numberEthernetII;
   int number8023;
   //Network layer vectors
   vector<int> ARP;
   vector<int> IPV4;
   vector<int> IPV6;
   int numberOtherNetworkLayer;
   //Transport layer vectors
   vector<int> ICMP;
   vector<int> TCP;
   vector<int> UDP;
   int numberOtherTransportLayer;
   //Network layer average, max, min sizes
   int averageARP, minimumARP, maximumARP;
   int averageIPV4, minimumIPV4, maximumIPV4;
   int averageIPV6, minimumIPV6, maximumIPV6;
   //Transport layer average, max, min sizes
   int averageICMP, minimumICMP, maximumICMP;
   int averageTCP, minimumTCP, maximumTCP;
   int averageUDP, minimumUDP, maximumUDP;



  public:
   resultsC();
   void incrementPacketCount() { totalPacketCount++; };
   //Push back values to keep track of data of each known protocol type
   void pushBackARP(int value){ ARP.push_back(value);};
   void pushBackIPV4(int value){ IPV4.push_back(value);};
   void pushBackIPV6(int value){ IPV6.push_back(value);};
   void pushBackICMP(int value){ ICMP.push_back(value);};
   void pushBackTCP(int value){ TCP.push_back(value);};
   void pushBackUDP(int value){ UDP.push_back(value);};
   //Get the average value of an int array
   int getAverage(vector<int> v){
	//Keep track of the sum of each argument
   	int sum = 0;
	//iteration using simple for loop
	for(int i = 0; i < v.size(); i++){
		sum += v[i];
	}
	int average = (sum/v.size());
	return average;
   }; 
   int getAverageARP(){
	return getAverage(ARP);
   };
   void displayResults();
};

#endif
