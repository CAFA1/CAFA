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
 * This tool checks that Pin reports static and dynamic symbols correctly. The tool assumes two
 * symbols defined in the application: statdyn_app_staticFunction (static symbol) and
 * statdyn_app_dynamicFunction (dynamic symbol). The tool makes sure that these symbols are
 * found and defined correctly.
 */

#include "pin.H"
#include <cassert>

VOID onImageLoad(IMG img, VOID *data)
{
    SYM sym;

    if (IMG_IsMainExecutable(img))
    {
        bool foundStatic = false;
        bool foundDynamic = false;
        for (sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
        {
            if (SYM_Name(sym).find("statdyn_app_staticFunction") != string::npos)
            {
                assert(SYM_Dynamic(sym) == false);
                foundStatic = true;
            }
            if (SYM_Name(sym).find("statdyn_app_dynamicFunction") != string::npos)
            {
                assert(SYM_Dynamic(sym) == true);
                foundDynamic = true;
            }
        }
        assert(foundStatic == true);
        assert(foundDynamic == true);
    }
}


int main(int argc, char** argv)
{
    PIN_InitSymbols();
    
    if (!PIN_Init(argc, argv))
    {

        IMG_AddInstrumentFunction(onImageLoad,  0);

        PIN_StartProgram();
    }

    return(1);
}
