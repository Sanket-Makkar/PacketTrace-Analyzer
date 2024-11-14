/*  Name: Sanket Makkar
    CaseID:         sxm1626
    File Name:      TraceAnalyzer.h
    Date Created:   11/5/2024
    Description:    The purpose of this file is to define a header for the core functionality
                    as required by this assignment for the Trace Analyzer.
*/
#ifndef TRACE_ANALYZER_H
#define TRACE_ANALYZER_H

#include <string>
#include <vector>

#define MAX_PKT_SIZE        1600

using namespace std;

class TraceAnalyzer{
    private:
        int args;
        string traceFile;

        /* meta information, using same layout as trace file */
        struct meta_info
        {
            unsigned int secs;
            unsigned int usecs;
            unsigned short caplen;
            unsigned short ignored;
        };
        
        /* record of information about the current packet */
        struct pkt_info
        {
            unsigned short caplen;      /* from meta info */
            double now;                 /* from meta info */
            unsigned char pkt [MAX_PKT_SIZE];
            struct ether_header *ethh;  /* ptr to ethernet header, if present,
                                        otherwise NULL */
            struct iphdr *iph;          /* ptr to IP header, if present, 
                                        otherwise NULL */
            struct tcphdr *tcph;        /* ptr to TCP header, if present,
                                        otherwise NULL */
            struct udphdr *udph;        /* ptr to UDP header, if present,
                                        otherwise NULL */
        };

        /* Useful struct for the matrix mode*/
        struct ipTraceInfo{
            unsigned int srcIp;
            unsigned int destIp;
            unsigned int totalPackets;
            unsigned int trafficVolume;
        };

        // core logic
        unsigned short nextPacket(int fd, struct pkt_info *pinfo); // get a packet
        void infoParse(int fd); // -i
        void sizeParse(int fd); // -s
        void tcpPacketPrintingParse(int fd); // -t
        void matrixParse(int fd); // -m

        // helpers
        unsigned int hashFunction(unsigned int src, unsigned int dst); // hash two numbers for a unique number
        string findQuads(unsigned int ip); // number --> ipv4 addr with dotted quads
        void printError(string error); // inform the user of an error
    public:
        TraceAnalyzer(int argLine, string givenTraceFile); // basic constructor
        ~TraceAnalyzer() = default; // nothing special for destructor

        // what the user calls to parse their packets after initialization (which is effectively the setup step)
        void parsePackets();
};

#endif // TRACE_ANALYZER_H