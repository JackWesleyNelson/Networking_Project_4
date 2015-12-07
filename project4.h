//
//  project4.h
//  Project4
//
//  Created by Phillip Romig on 4/3/12.
//  Copyright 2012 Colorado School of Mines. All rights reserved.
//

//Last edited 12/6/15 by Jack Wesley Nelson

#ifndef project4_h
#define project4_h

// System include files
#include <iostream>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <vector>
#include <utility>
#include <arpa/inet.h>
// Include files specific to this project.
#include "resultsC.h"

// Include files specific to this project.
void pk_processor(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif
