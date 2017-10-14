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
#include <stdio.h>
#include "pin.H"
#include <iostream>
#include <string.h>

// This tool looks for memcpy symbol if the symbol is IFUNC it prints "Found IFUNC memcpy"
// otherwise it prints "Found non IFUNC memcpy"
// The tool also adds an istrumentation functions before the memcpy that 
// prints "memcpy called" in case of non IFUNC memcpy and "ifunc memcpy called" in case of IFUNC memcpy

VOID Memcpy(ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
    cout << "memcpy called" << endl;
}
VOID IfuncMemcpy()
{
    cout << "ifunc memcpy called" << endl;
}

VOID Routine(RTN rtn, void * v)
{
    RTN_Open(rtn);
    if(strcmp(RTN_Name(rtn).c_str(),"memcpy")==0)
    {
        if(SYM_IFunc(RTN_Sym(rtn)))
        {
            cout << "Found IFUNC memcpy"<< endl;
            RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(IfuncMemcpy), IARG_END);
        }
        else
        {
            cout << "Found non IFUNC memcpy"<< endl;
            RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(Memcpy), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2 , IARG_END);
        }
    }
    RTN_Close(rtn);
}


VOID Image(IMG img, void * v)
{
    cout << "IMG = " << IMG_Name(img) << endl;
    for( SEC sec=IMG_SecHead(img); SEC_Valid(sec) ; sec=SEC_Next(sec) )
    {
        if ( SEC_IsExecutable(sec) )
        {
            for( RTN rtn=SEC_RtnHead(sec); RTN_Valid(rtn) ; rtn=RTN_Next(rtn) )
                Routine(rtn,v);
        }
    }
}


int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbolsAlt( SYMBOL_INFO_MODE(UINT32(IFUNC_SYMBOLS) |  UINT32(DEBUG_OR_EXPORT_SYMBOLS)));

    IMG_AddInstrumentFunction(Image,0);
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}
