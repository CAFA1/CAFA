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
 * This tool verifies that Pin can deliver signals on traces with
 * different types of instrumentation calls.  This tool must be run
 * with the application "inst-type.cpp"; it searches for specific
 * functions in that application and inserts different types of
 * instrumentation at each one.
 */

#include <iostream>
#include <cstdlib>
#include "pin.H"

#if defined(TARGET_IA32) || defined(TARGET_IA32E)
    // IARG_CONTEXT should force Pin to create a bridge routine.  However,
    // IARG_CONTEXT is not allowed in an "if" analysis call, so we use
    // IARG_REG_REFERENCE, which should also force usage of a bridge.
    //
#   define IARG_BRIDGE      IARG_CONTEXT
#   define IARG_BRIDGE_IF   IARG_REG_REFERENCE, REG_STACK_PTR
#endif

static VOID OnRoutine(RTN, VOID *);
static VOID InsertInline(RTN rtn);
static VOID InsertNoBridge(RTN rtn);
static VOID InsertBridge(RTN rtn);
static VOID InsertIfInlineThenInline(RTN rtn);
static VOID InsertIfInlineThenNoBridge(RTN rtn);
static VOID InsertIfInlineThenBridge(RTN rtn);
static VOID InsertIfNoBridgeThenInline(RTN rtn);
static VOID InsertIfNoBridgeThenNoBridge(RTN rtn);
static VOID InsertIfNoBridgeThenBridge(RTN rtn);
static VOID InsertIfBridgeThenInline(RTN rtn);
static VOID InsertIfBridgeThenNoBridge(RTN rtn);
static VOID InsertIfBridgeThenBridge(RTN rtn);
static VOID Inline();
static VOID NoBridge();
static VOID Bridge();
static ADDRINT IfInline();
static ADDRINT IfNoBridge();
static ADDRINT IfBridge();
static VOID ThenInline();
static VOID ThenNoBridge();
static VOID ThenBridge();
static VOID ForceOutOfLine();
static VOID OnExit(INT32, VOID *);

static BOOL GotInline = FALSE;
static BOOL GotNoBridge = FALSE;
static BOOL GotBridge = FALSE;
static BOOL GotIfInline = FALSE;
static BOOL GotIfNoBridge = FALSE;
static BOOL GotIfBridge = FALSE;
static BOOL GotThenInline = FALSE;
static BOOL GotThenNoBridge = FALSE;
static BOOL GotThenBridge = FALSE;

typedef VOID (*FUN)();


int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();

    RTN_AddInstrumentFunction(OnRoutine, 0);
    PIN_AddFiniFunction(OnExit, 0);

    PIN_StartProgram();
    return 0;
}

#ifdef TARGET_MAC
static VOID OnRoutine(RTN rtn, VOID *)
{
    if (RTN_Name(rtn) == "_DoInline" || RTN_Name(rtn) == "_DoAll")
        InsertInline(rtn);
    if (RTN_Name(rtn) == "_DoNoBridge" || RTN_Name(rtn) == "_DoAll")
        InsertNoBridge(rtn);
    if (RTN_Name(rtn) == "_DoBridge" || RTN_Name(rtn) == "_DoAll")
        InsertBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfInlineThenInline" || RTN_Name(rtn) == "_DoAll")
        InsertIfInlineThenInline(rtn);
    if (RTN_Name(rtn) == "_DoIfInlineThenNoBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfInlineThenNoBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfInlineThenBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfInlineThenBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfNoBridgeThenInline" || RTN_Name(rtn) == "_DoAll")
        InsertIfNoBridgeThenInline(rtn);
    if (RTN_Name(rtn) == "_DoIfNoBridgeThenNoBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfNoBridgeThenNoBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfNoBridgeThenBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfNoBridgeThenBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfBridgeThenInline" || RTN_Name(rtn) == "_DoAll")
        InsertIfBridgeThenInline(rtn);
    if (RTN_Name(rtn) == "_DoIfBridgeThenNoBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfBridgeThenNoBridge(rtn);
    if (RTN_Name(rtn) == "_DoIfBridgeThenBridge" || RTN_Name(rtn) == "_DoAll")
        InsertIfBridgeThenBridge(rtn);
}
#else
static VOID OnRoutine(RTN rtn, VOID *)
{
    if (RTN_Name(rtn) == "DoInline" || RTN_Name(rtn) == "DoAll")
        InsertInline(rtn);
    if (RTN_Name(rtn) == "DoNoBridge" || RTN_Name(rtn) == "DoAll")
        InsertNoBridge(rtn);
    if (RTN_Name(rtn) == "DoBridge" || RTN_Name(rtn) == "DoAll")
        InsertBridge(rtn);
    if (RTN_Name(rtn) == "DoIfInlineThenInline" || RTN_Name(rtn) == "DoAll")
        InsertIfInlineThenInline(rtn);
    if (RTN_Name(rtn) == "DoIfInlineThenNoBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfInlineThenNoBridge(rtn);
    if (RTN_Name(rtn) == "DoIfInlineThenBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfInlineThenBridge(rtn);
    if (RTN_Name(rtn) == "DoIfNoBridgeThenInline" || RTN_Name(rtn) == "DoAll")
        InsertIfNoBridgeThenInline(rtn);
    if (RTN_Name(rtn) == "DoIfNoBridgeThenNoBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfNoBridgeThenNoBridge(rtn);
    if (RTN_Name(rtn) == "DoIfNoBridgeThenBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfNoBridgeThenBridge(rtn);
    if (RTN_Name(rtn) == "DoIfBridgeThenInline" || RTN_Name(rtn) == "DoAll")
        InsertIfBridgeThenInline(rtn);
    if (RTN_Name(rtn) == "DoIfBridgeThenNoBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfBridgeThenNoBridge(rtn);
    if (RTN_Name(rtn) == "DoIfBridgeThenBridge" || RTN_Name(rtn) == "DoAll")
        InsertIfBridgeThenBridge(rtn);
}
#endif

static VOID InsertInline(RTN rtn)
{
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(Inline), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertNoBridge(RTN rtn)
{
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(NoBridge), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertBridge(RTN rtn)
{
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(Bridge), IARG_BRIDGE, IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfInlineThenInline(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfInline), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenInline), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfInlineThenNoBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfInline), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenNoBridge), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfInlineThenBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfInline), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenBridge), IARG_BRIDGE, IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfNoBridgeThenInline(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfNoBridge), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenInline), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfNoBridgeThenNoBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfNoBridge), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenNoBridge), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfNoBridgeThenBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfNoBridge), IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenBridge), IARG_BRIDGE, IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfBridgeThenInline(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfBridge), IARG_BRIDGE_IF, IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenInline), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfBridgeThenNoBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfBridge), IARG_BRIDGE_IF, IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenNoBridge), IARG_END);
    RTN_Close(rtn);
}

static VOID InsertIfBridgeThenBridge(RTN rtn)
{
    RTN_Open(rtn);
    INS_InsertIfCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(IfBridge), IARG_BRIDGE_IF, IARG_END);
    INS_InsertThenCall(RTN_InsHead(rtn), IPOINT_BEFORE, AFUNPTR(ThenBridge), IARG_BRIDGE, IARG_END);
    RTN_Close(rtn);
}

static VOID Inline()
{
    GotInline = TRUE;
}

static VOID NoBridge()
{
    GotNoBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
}

static VOID Bridge()
{
    GotBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
}

static ADDRINT IfInline()
{
    GotIfInline = TRUE;
    return 1;
}

static ADDRINT IfNoBridge()
{
    GotIfNoBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
    return 1;
}

static ADDRINT IfBridge()
{
    GotIfBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
    return 1;
}

static VOID ThenInline()
{
    GotThenInline = TRUE;
}

static VOID ThenNoBridge()
{
    GotThenNoBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
}

static VOID ThenBridge()
{
    GotThenBridge = TRUE;
    volatile FUN fn = ForceOutOfLine;
    fn();
}

static VOID ForceOutOfLine()
{
}


static VOID OnExit(INT32, VOID *)
{
    if (!GotInline || !GotNoBridge || !GotBridge ||
        !GotIfInline || !GotIfNoBridge || !GotIfBridge ||
        !GotThenInline || !GotThenNoBridge || !GotThenBridge)
    {
        std::cerr << "Analysis routine not exectued." << std::endl;
        std::exit(1);
    }
}
