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
#include <set>
//pair is used to check unique ipv6 addresses
#include <utility> 

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
   //Part 2 sets
   set<const u_char*> unique_MAC;
   typedef pair<uint64_t, int64_t> Address;
   set<Address> unique_IPV6;
   set<char*> unique_IPV4;
   set<u_char> unique_UDP;
   set<u_char> unique_TCP;
   //Part 2 counts
   int numberSYN;
   int numberFIN;
   int numberFragmented;
  public:
   resultsC();
   //Increment the counters for non vector information types.
   void incrementPacketCount() { totalPacketCount++; };
   void incrementEthernetIICount(){ numberEthernetII++; };
   void increment8023Count(){ number8023++; };
   void incrementOtherNetworkLayerCount(){ numberOtherNetworkLayer++; };
   void incrementOtherTransportLayerCount(){ numberOtherTransportLayer++; };
   void incrementSYN(){numberSYN++;};
   void incrementFIN(){numberFIN++;};
   void incrementFragmented(){numberFragmented++;};
   //Push back values to keep track of data of each known protocol type
   void pushBackARP(int value){ ARP.push_back(value);};
   void pushBackIPV4(int value){ IPV4.push_back(value);};
   void pushBackIPV6(int value){ IPV6.push_back(value);};
   void pushBackICMP(int value){ ICMP.push_back(value);};
   void pushBackTCP(int value){ TCP.push_back(value);};
   void pushBackUDP(int value){ UDP.push_back(value);};
   //Inserts for part II sets
   void insertMAC(const u_char* value){unique_MAC.insert(value);};
   void insertIPV4(char* value){unique_IPV4.insert(value);};
   void insertUDP(u_char value){unique_UDP.insert(value);};
   void insertTCP(u_char value){unique_TCP.insert(value);};
   void insertIPV6(pair<uint64_t, int64_t> value){unique_IPV6.insert(value);};
   //Get the average value of an int vector
   int getAverage(vector<int> v){
	//If the vector is empty, return 0.
	if(v.size() == 0){
		return 0;
	}
	//Keep track of the sum of each argument
   	int sum = 0;
	//iteration using simple for loop
	for(int i = 0; i < v.size(); i++){
		sum += v[i];
	}
	int average = (sum/v.size());
	return average;
   };
   //Get average of the specific vectors
   int getAverageARP(){
	return getAverage(ARP);
   };
   int getAverageIPV4(){
	return getAverage(IPV4);
   };
   int getAverageIPV6(){
	return getAverage(IPV6);
   };
   int getAverageICMP(){
	return getAverage(ICMP);
   };
   int getAverageTCP(){
	return getAverage(TCP);
   };
   int getAverageUDP(){
	return getAverage(UDP);
   };
   //Get the minimum value in an int vector
   int getMinimum(vector<int> v){
	//If the vector is empty, return 0.
	if(v.size() == 0){
		return 0;
	}
   	//Keep track of current lowest
	int min = -1;
	//iteration using simple for loop
	for(int i = 0; i < v.size(); i++){
		if(min > v[i] || min == -1){
			min = v[i];
		}
	}
	return min;
   };
   //Get the minimum value of the specific vectors
   int getMinimumARP(){
	return getMinimum(ARP);
   };
   int getMinimumIPV4(){
	return getMinimum(IPV4);
   };
   int getMinimumIPV6(){
	return getMinimum(IPV6);
   };
   int getMinimumICMP(){
	return getMinimum(ICMP);
   };
   int getMinimumTCP(){
	return getMinimum(TCP);
   };
   int getMinimumUDP(){
	return getMinimum(UDP);
   };
   //Get the maximum value in an int vector
   int getMaximum(vector<int> v){
	//If the vector is empty, return 0.
	if(v.size() == 0){
		return 0;
	}
   	//Keep track of current largest
	int max = -1;
	//iteration using simple for loop
	for(int i = 0; i < v.size(); i++){
		if(max < v[i] || max == -1){
			max = v[i];
		}
	}
	return max;
   };
   //Get the maximum of the specific vectors
   int getMaximumARP(){
	return getMaximum(ARP);
   };
   int getMaximumIPV4(){
	return getMaximum(IPV4);
   };
   int getMaximumIPV6(){
	return getMaximum(IPV6);
   };
   int getMaximumICMP(){
	return getMaximum(ICMP);
   };
   int getMaximumTCP(){
	return getMaximum(TCP);
   };
   int getMaximumUDP(){
	return getMaximum(UDP);
   };
   //Get the count of the specific vectors
   int getCountARP(){
	return ARP.size();
   };
   int getCountIPV4(){
	return IPV4.size();
   };
   int getCountIPV6(){
	return IPV6.size();
   };
   int getCountICMP(){
	return ICMP.size();
   };
   int getCountTCP(){
	return TCP.size();
   };
   int getCountUDP(){
	return UDP.size();
   };
   int getCountUniqueMAC(){
	return unique_MAC.size();
   };
   int getCountUniqueIPV4(){
	return unique_IPV4.size();
   };
   int getCountUniqueIPV6(){
	return unique_IPV6.size();
   };
   int getCountUniqueUDP(){
	return unique_UDP.size();
   };
   int getCountUniqueTCP(){
	return unique_TCP.size();
   };

   void displayResults();
};

#endif
