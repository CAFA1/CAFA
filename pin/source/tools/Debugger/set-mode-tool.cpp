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
 * This tool enables PinADX debugging via PIN_SetDebugMode().  It should be
 * run without -appdebug.
 */
 
#include <iostream>
#include "pin.H"


static void OnThreadStart(THREADID, CONTEXT *, INT32, VOID *);


int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);

    if (PIN_GetDebugStatus() != DEBUG_STATUS_DISABLED)
    {
        std::cerr << "Expected DISABLED status initially" << std::endl;
        return 1;
    }

    DEBUG_MODE mode;
    mode._type = DEBUG_CONNECTION_TYPE_TCP_SERVER;
    mode._options = DEBUG_MODE_OPTION_STOP_AT_ENTRY;
    if (!PIN_SetDebugMode(&mode))
    {
        std::cerr << "Error from PIN_SetDebugMode()" << std::endl;
        return 1;
    }

    if (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTABLE)
    {
        std::cerr << "Expected UNCONNECTABLE status in main" << std::endl;
        return 1;
    }

    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_StartProgram();
    return 0;
}

static void OnThreadStart(THREADID, CONTEXT *, INT32, VOID *)
{
    DEBUG_STATUS status = PIN_GetDebugStatus();
    if (status != DEBUG_STATUS_UNCONNECTED && status != DEBUG_STATUS_CONNECTED)
    {
        std::cerr << "Expected UNCONNECTED / CONNECTED status after application started" << std::endl;
        PIN_ExitProcess(1);
    }

    if (!PIN_WaitForDebuggerToConnect(0))
    {
        std::cerr << "Error from PIN_WaitForDebuggerToConnect()" << std::endl;
        PIN_ExitProcess(1);
    }
}
