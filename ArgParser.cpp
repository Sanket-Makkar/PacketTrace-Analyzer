/*  Name: Sanket Makkar
    CaseID:         sxm1626
    File Name:      ArgParser.cpp
    Date Created:   10/17/2024
    Description:    This file contains implementations for functions described within ArgParser.h.
                    In general, this class is intended to provide a set of methods helpful to any
                    other file that may want to parse, or perform some parsing-related action, on
                    user input.
*/

#include "ArgParser.h"  
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <list>
#include <string>
#include <string.h>
#include <vector>

using namespace std;

// These are flags we will check for and set
#define ARG_TRACE_FILE 0x1
#define ARG_TRACE_INFORMATION_MODE 0x2
#define ARG_SIZE_ANALYSIS_MODE 0x4
#define ARG_PACKET_PRINTING_MODE 0x8
#define ARG_MATRIX_MODE 0x10

// Basic counter related constants
#define COUNTER_INITIALIZER 0
#define OFF_BY_ONE_OFFSET 1

#define FIRST_VALUE 0
#define EMPTY_CLI_ARGS 0

// rather than writing exit(-1) every time I want to exit with an error, I wrote up this macro to make it easier
#define exitWithErr exit(-1)

string foundTraceFileLocation;
unsigned int cmdLineFlags = 0x00000;

// We take an input of argc, argv from the caller - arguments and number of arguments, as well as two callbacks to execute at the end of the function call
int parseArgs(int argc, char *argv[], void (*grabTraceFileLocation)(string fileLocation)){
    int opt;
    while ((opt = getopt(argc, argv, "ismtr:")) != -1){
        // check for cases of prt
        switch (opt){
            case 'r': 
                checkNonSetFlag(cmdLineFlags, ARG_TRACE_FILE, 'r'); // don't let the user enter a flag more than one time
                cmdLineFlags |= ARG_TRACE_FILE;
                foundTraceFileLocation = optarg;
                break;
            case 'i': 
                checkNonSetFlag(cmdLineFlags, ARG_TRACE_INFORMATION_MODE, 'i'); // don't let the user enter a flag more than one time
                cmdLineFlags |= ARG_TRACE_INFORMATION_MODE;
                break;
            case 's': 
                checkNonSetFlag(cmdLineFlags, ARG_SIZE_ANALYSIS_MODE, 's'); // don't let the user enter a flag more than one time
                cmdLineFlags |= ARG_SIZE_ANALYSIS_MODE;
                break;
            case 'm': 
                checkNonSetFlag(cmdLineFlags, ARG_MATRIX_MODE, 'm'); // don't let the user enter a flag more than one time
                cmdLineFlags |= ARG_MATRIX_MODE;
                break;
            case 't': 
                checkNonSetFlag(cmdLineFlags, ARG_PACKET_PRINTING_MODE, 't'); // don't let the user enter a flag more than one time
                cmdLineFlags |= ARG_PACKET_PRINTING_MODE;
                break;
            case '?': // if invalid option provided, react with an error message and exit
                usage(argv[FIRST_VALUE]);
                exitWithErr;
            default: // and if nothing else gets caught then just react with an error message and exit
                usage(argv[FIRST_VALUE]);
        }
    }

    if (!flagsContainBit(cmdLineFlags, ARG_TRACE_FILE)){
        fprintf(stderr, "Error: provide trace file\n");
        exitWithErr;
    }
    
    vector<int> requireOneFlag = {ARG_MATRIX_MODE, ARG_SIZE_ANALYSIS_MODE, ARG_PACKET_PRINTING_MODE, ARG_TRACE_INFORMATION_MODE};
    if (!checkOnlyHasOneFlag(cmdLineFlags, requireOneFlag)){
        fprintf(stderr, "Error: provide precisely one argument, not multiple, and at least one\n");
        exitWithErr;
    }

    grabTraceFileLocation(foundTraceFileLocation);

    return cmdLineFlags;
}

// more universal helper to ensure the flags contain a specified bit
bool flagsContainBit(int cmdFlags, int bit){ 
    if (cmdFlags & bit){
        return true;
    }
    return false;
}

// verify a flag was not set
void checkNonSetFlag(int cmdFlags, int bit, char arg){
    if (flagsContainBit(cmdFlags, bit)){
        fprintf(stderr, "Error: failed user entry (2 instances of -%c)\n", arg);
        exitWithErr;
    }
}

bool checkOnlyHasOneFlag(int cmdFlags, vector<int> flagsVector){
    bool encountered = false;
    for (int flag : flagsVector){ // look through flag vector
        if (flagsContainBit(cmdFlags, flag)){ // if we have a flag
            if (encountered) // ... and we have already seen a flag in the vector - we have two --> return false
                return false;
            encountered = true; // ... otherwise mark that we have found a flag and move on
        }
    }
    return encountered; // now if we found a flag then we inform the user, but if not this will inform them as well
}

// inform the user of the flags available to use this program
void usage(char *progname){
    fprintf(stderr, "%s -r trace_file -i|-s|-t|-m\n", progname);
    fprintf(stderr, "   -r trace_file           (REQUIRED) provide a trace file to analyze\n");
    fprintf(stderr, "   ------------------------------------------------\n   Give exactly  one of the options below\n   ------------------------------------------------\n");
    fprintf(stderr, "   -i                      trace information mode\n");
    fprintf(stderr, "   -s                      size analysis mode\n");
    fprintf(stderr, "   -t                      TCP packet printing mode\n");
    fprintf(stderr, "   -m                      matrix mode\n");
    exitWithErr;
}