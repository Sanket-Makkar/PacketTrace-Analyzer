/*  Name: Sanket Makkar
    CaseID:         sxm1626
    File Name:      TraceAnalyzer.cpp
    Date Created:   10/19/2024
    Description:    The purpose of this file is to implement the core functionality for the web-server as required 
                    by this assignment. This file in particular implements the methods intended to do this work as 
                    defined within the TraceAnalyzer.h header file.
*/
#include "TraceAnalyzer.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>

// Argument Flags

// Helpful variables for initialization of counters, handling off-by-one errors, and comparisons
#define COUNTER_INITIAL_VALUE 0
#define OFF_BY_ONE_OFFSET 1
#define DECREMENT -1
#define FUNCTION_ERROR_RETURN_VALUE -1
#define BUFLEN 1024
#define WORD_TO_BYTE 4

// Useful header constants
#define ETH_HDR_LEN 14
#define MIN_IP_HDR_LEN 20
#define MIN_SIZE_UP_TO_IP (ETH_HDR_LEN + MIN_IP_HDR_LEN)

// exit options
#define exitWithErr exit(FUNCTION_ERROR_RETURN_VALUE)
#define exitWithNoErr exit(COUNTER_INITIAL_VALUE)

using namespace std;

TraceAnalyzer::TraceAnalyzer(int argLine, string givenTraceFile): traceFile(givenTraceFile) {}

void TraceAnalyzer::parsePackets(){
    int fd = open(traceFile.c_str(), 'r');
    pkt_info info;
    nextPacket(fd, &info);
    printf("%f\n", info.now);
    exit(0);
}

unsigned short TraceAnalyzer::nextPacket (int fd, struct pkt_info *pinfo)
{
    struct meta_info meta;
    long unsigned int bytes_read;

    memset (pinfo,0x0,sizeof (struct pkt_info));
    memset (&meta,0x0,sizeof (struct meta_info));

    /* read the meta information */
    bytes_read = read (fd,&meta,sizeof (meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < sizeof (meta))
        printError("cannot read meta information");
    
    /* grab and set caplen */
    pinfo->caplen = ntohs (meta.caplen);
    
    /* set pinfo->now based on meta.secs & meta.usecs */
    unsigned int seconds = ntohl(meta.secs);
    unsigned int microsecs = ntohl(meta.usecs);
    pinfo->now = double(seconds + (microsecs/1000000.0));

    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        printError("packet too big");

    /* read the packet contents */
    bytes_read = read (fd,pinfo->pkt,pinfo->caplen);
    if (bytes_read < 0)
        printError("error reading packet");
    if (bytes_read < pinfo->caplen)
        printError("unexpected end of file encountered");
    if (bytes_read < sizeof (struct ether_header))
        return (1);
    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs (pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof (struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);
    /* TODO:
       set pinfo->iph to start of IP header
       if TCP packet, 
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed
       if UDP packet, 
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */
    
    // set iph for pinfo and check that we can fit it
    pinfo->iph = (struct iphdr *)(pinfo->pkt + ETH_HDR_LEN);
    if (pinfo->caplen < MIN_SIZE_UP_TO_IP)
        return(1);
    
    if (pinfo->iph->protocol == IPPROTO_TCP){
        pinfo->tcph = (struct tcphdr *)(pinfo->pkt + (pinfo->iph->ihl * WORD_TO_BYTE));
        // may need to look here for sp dp
    }
    else if(pinfo->iph->protocol == IPPROTO_UDP){
        pinfo->udph = (struct udphdr *)(pinfo->pkt + (pinfo->iph->ihl * WORD_TO_BYTE));
        // again, sp dp might be needed in the future
    }

    // maybe check size as well

    return (1);
}

void TraceAnalyzer::printError(string error){
    fprintf(stderr, "%s\n", error.c_str());
    exitWithErr;
}