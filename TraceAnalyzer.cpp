/*  Name: Sanket Makkar
    CaseID:         sxm1626
    File Name:      TraceAnalyzer.cpp
    Date Created:   10/19/2024
    Description:    The purpose of this file is to implement the core functionality for the web-server as required 
                    by this assignment. This file in particular implements the methods intended to do this work as 
                    defined within the TraceAnalyzer.h header file.
*/
#include "TraceAnalyzer.h"
#include "ArgParser.h"
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
#define ARG_TRACE_FILE 0x1
#define ARG_TRACE_INFORMATION_MODE 0x2
#define ARG_SIZE_ANALYSIS_MODE 0x4
#define ARG_PACKET_PRINTING_MODE 0x8
#define ARG_MATRIX_MODE 0x10

// Helpful variables for initialization of counters, handling off-by-one errors, and comparisons
#define COUNTER_INITIAL_VALUE 0
#define OFF_BY_ONE_OFFSET 1
#define DECREMENT -1
#define FUNCTION_ERROR_RETURN_VALUE -1
#define BUFLEN 1024
#define WORD_TO_BYTE 4

// Useful header constants
#define MIN_SIZE_UP_TO_IP (sizeof(struct ether_header) + sizeof(struct iphdr))
#define ETH_HEADER_LEN 14

// exit options
#define exitWithErr exit(FUNCTION_ERROR_RETURN_VALUE)
#define exitWithNoErr exit(COUNTER_INITIAL_VALUE)

using namespace std;

TraceAnalyzer::TraceAnalyzer(int argLine, string givenTraceFile): args(argLine), traceFile(givenTraceFile) {}

void TraceAnalyzer::parsePackets(){
    // now lets open the file
    int fd = open(traceFile.c_str(), 'r');
    if (fd < 0){
        printError("Failure to open tracefile, please provide and request a valid trace file.\n");
    }

    if (flagsContainBit(args, ARG_TRACE_INFORMATION_MODE))
        infoParse(fd);
    else if(flagsContainBit(args, ARG_SIZE_ANALYSIS_MODE))
        sizeParse(fd);
    else if(flagsContainBit(args, ARG_PACKET_PRINTING_MODE))
        packetPrintingParse(fd);
    
    close(fd);
    exit(0);
}

void TraceAnalyzer::infoParse(int fd){
    /* [tracefilename] [firsttime] [duration = lasttime - firsttime] [totalPackets] [IP_pkts] */
    pkt_info info; // lets get a packet
    double firstTime = -1;
    double lastTime;
    long unsigned int packetCounter = 0;
    long unsigned int ipPackets = 0;
    while (nextPacket(fd, &info) > 0){
        // figure out the first time, as well as last time (for duration calculation) here.
        if (firstTime == -1)
            firstTime = info.now;
        lastTime = info.now;

        // count packets size
        packetCounter++;
        
        // determine ip packets amount -- TODO: fix
        if (info.iph != NULL){
            ipPackets++;
        }

        memset(&info, 0, sizeof(struct pkt_info)); // once we have finished processing, reset info
    }
    printf("%s %f %f %lu %lu\n", traceFile.c_str(), firstTime, (lastTime - firstTime), packetCounter, ipPackets);
}

void TraceAnalyzer::sizeParse(int fd){
    /* for each ipv4 packet:
        [timestamp = now] [caplen] [ip total length] [length of ip header (iphl)] \
            [Transport - T if TCP, U if UDP] [transhl = bytes in tcp/udp hdr] \ 
            [payload len = lenpkt - caplen] 
    */
    pkt_info info;
    while (nextPacket(fd, &info) > 0){
        double timeStamp;
        unsigned short caplen;
        string totalIPLength = "-";
        string iphLen = "-";
        char transportType = '-';
        string transHL = "-";
        string payloadLen = "-";
        if (info.iph == NULL){
            // not an ipv4 packet - so no ipv4 header
            continue;
        }
        else{
            // grab total ip length
            int intTotalIPLength = ntohs(info.iph->tot_len);
            totalIPLength = to_string(intTotalIPLength);

            // length of ip header determined here
            unsigned int intIphLen = info.iph->ihl * WORD_TO_BYTE;
            iphLen = to_string(intIphLen);

            // transport type and length -- TODO: fix
            transportType = '?';
            transHL = "?";
            unsigned int intTransHL = 0;
            bool foundUDPorTCP = false;
            if (info.tcph != NULL){
                transportType = 'T';
                intTransHL = info.tcph->th_off * 4;
                foundUDPorTCP = true;
            }
            else if (info.udph != NULL){
                transportType = 'U';
                intTransHL = ntohl(info.udph->uh_ulen);
                foundUDPorTCP = true;
            }
            
            if (foundUDPorTCP == true){ // in the case we do have TCP or UDP
                transHL = to_string(intTransHL);
                uint intPayloadLen =  intTotalIPLength - intIphLen - intTransHL;
                payloadLen = to_string(intPayloadLen);
            }
            else{
                payloadLen = "?";
            }
        }
        // grab timestamp
        timeStamp = info.now;

        // grab caplen
        caplen = info.caplen;

        printf("%f %u %s %s %c %s %s\n", timeStamp, caplen, totalIPLength.c_str(), iphLen.c_str(), transportType, transHL.c_str(), payloadLen.c_str());
        memset(&info, 0, sizeof(struct pkt_info)); // once we have finished processing, reset info
    }
}

void TraceAnalyzer::packetPrintingParse(int fd){
    /* [] */

    pkt_info info;

    while(nextPacket(fd, &info)){


        memset(&info, 0, sizeof(struct pkt_info));
    }
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
    
    /* grab ethernet header */
    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs (pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof (struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);

    /* set pinfo->iph to start of IP header
       if TCP packet, 
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed
       if UDP packet, 
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */
    
    // set iph for pinfo and check that we can fit it
    pinfo->iph = (struct iphdr *)(pinfo->pkt + sizeof(struct ether_header));
    if (pinfo->caplen < MIN_SIZE_UP_TO_IP)
        return(1);
    
    if (pinfo->iph->protocol == IPPROTO_TCP){
        pinfo->tcph = (struct tcphdr *)(pinfo->pkt + sizeof(struct ether_header) + (pinfo->iph->ihl * WORD_TO_BYTE));
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