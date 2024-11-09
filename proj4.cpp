/*  Name: Sanket Makkar
    CaseID:         sxm1626
    File Name:      proj4.cpp
    Date Created:   11/17/2024
    Description:    This is the file that contains a main function for the simple CLI web-based server.
                    The point behind making this file is mostly to orchestrate functionality held within other
                    files of this project.
*/
#include <stdio.h>
#include "ArgParser.h"
#include <string>
#include <string.h>

using namespace std;

string traceFileLocation;

void saveTraceFileLocation(string fileLocation){
    traceFileLocation = fileLocation;
}

int main(int argc, char *argv[]){
    // execute parse args, passing in a callback that will grab file name, and returning/storing the args flag indicator
    int argLine = parseArgs(argc, argv, saveTraceFileLocation);

    printf("argline = %x\nfileLocation = %s\n", argLine, traceFileLocation.c_str());

    return 0;
}
