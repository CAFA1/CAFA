/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2012 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 * This tool verifies that the registered image unload callback is being called when the image: one.dll(for windows)/one.so(for unix)
 * has been unloaded
 */

#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include <iostream> 
#include <string>

using namespace std;

#if defined (TARGET_WINDOWS)      
const string so_name = "one.dll";
#else
const string so_name = "one.so";
#endif

const string function_name = "one"; 
 
VOID ImageUnload(IMG img, VOID *v)
{   
    if( IMG_Name(img).find(so_name) != string::npos)
    {
        cout << "Unloaded " << IMG_Name(img) << endl;
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
            {
                if( RTN_Name(rtn).find(function_name)!= string::npos)
                {
                    int copySize;
                    CHAR * dst = (CHAR *)malloc(RTN_Size(rtn));
                    ASSERTX(dst != 0);
                    copySize = PIN_SafeCopy(dst, Addrint2VoidStar(RTN_Address(rtn)), RTN_Size(rtn));
                    ASSERT(((copySize == RTN_Size(rtn))), "SafeCopy failed.\n");
                    cout << "SafeCopy: Entire buffer has been copied successfully." << endl;
                }
            }   
        }
    }
    else 
    {
        cout << "Not found " << IMG_Name(img) << endl;
    }
} 

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
    PIN_ERROR(" This tool verifies that the registered image unload callback is called when an image has been unloaded\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
