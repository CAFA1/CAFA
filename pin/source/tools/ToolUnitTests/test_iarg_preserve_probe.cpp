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
#include <stdlib.h>
#include <pin.H>
#ifdef TARGET_WINDOWS
namespace WIND
{
#include <windows.h>
}
#define EXPORT_CSYM extern "C" __declspec( dllexport )
#else
#define EXPORT_CSYM extern "C" 
#endif

extern "C" BOOL ProcessorSupportsAvx();
#if defined(__cplusplus)
extern "C"
#endif
VOID FldzToTop3();
#if defined(__cplusplus)
extern "C"
#endif
VOID SetXmmRegsToZero();
#if defined(__cplusplus)
extern "C"
#endif
VOID SetIntRegsToZero();
#if defined(__cplusplus)
extern "C"
#endif
void UnMaskZeroDivideInMxcsr();

#if defined(__cplusplus)
extern "C"
#endif
double var1=2.0;
#if defined(__cplusplus)
extern "C"
#endif
double var2=2.0;
#if defined(__cplusplus)
extern "C"
#endif
double var3=2.0;


#define NUM_TESTS 4
static int testNum=0;

#if defined(__cplusplus)
extern "C"
#endif
VOID DummyProc()
{
}

EXPORT_CSYM void TestIargPreserveInReplacement()
{
}

EXPORT_CSYM void TestIargPreserveInReplacement1()
{
}

EXPORT_CSYM void TestIargPreserveInReplacement2()
{
}

EXPORT_CSYM void TestIargPreserveInProbed()
{
}

EXPORT_CSYM void TestIargPreserveInProbed1()
{
}

EXPORT_CSYM void TestIargPreserveInProbed2()
{
}


static UINT64 vals[]=
{1,0,2,0,3,0,4,0,5,0,6,0,7,0,8,0,9,0,10,0,11,0,12,0,13,0,14,0,15,0,16,0};

extern "C"  UINT64* val1=&vals[0];

extern "C"  UINT64* val2=&vals[2];

extern "C"  UINT64* val3=&vals[4];

extern "C"  UINT64* val4=&vals[6];

extern "C"  UINT64* val5=&vals[8];

extern "C"  UINT64* val6=&vals[10];

extern "C"  UINT64* val7=&vals[12];

extern "C"  UINT64* val8=&vals[14];

extern "C"  UINT64* val9=&vals[16];

extern "C"  UINT64* val10=&vals[18];

extern "C"  UINT64* val11=&vals[20];

extern "C"  UINT64* val12=&vals[22];

extern "C"  UINT64* val13=&vals[24];

extern "C"  UINT64* val14=&vals[26];

extern "C"  UINT64* val15=&vals[28];

extern "C"  UINT64* val16=&vals[30];

extern "C" ADDRINT setFlagsX=0;



#if defined(__cplusplus)
extern "C"
#endif
VOID TestIargPreserveReplacement()
{
    testNum++;
    FldzToTop3();
}

#if defined(__cplusplus)
extern "C"
#endif
VOID TestIargPreserveReplacement1()
{
    testNum++;
    FldzToTop3();
}

#if defined(__cplusplus)
extern "C"
#endif
VOID TestIargPreserveProbedBefore()
{
    testNum++;
    FldzToTop3();
}

#if defined(__cplusplus)
extern "C"
#endif
VOID TestIargPreserveProbedBefore1()
{
    testNum++;
    FldzToTop3();
}

VOID ImageLoad(IMG img, VOID *v)
{
    RTN rtn = RTN_FindByName(img, "TestIargPreserveInReplacement");

    if (RTN_Valid(rtn))
    {
        printf ("found TestIargPreserveInReplacement\n");
        fflush (stdout);
        PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                      "TestIargPreserveInReplacementProto", PIN_PARG_END() );
        REGSET regsFP;
        REGSET_Clear(regsFP);
        REGSET_Insert (regsFP, REG_X87);
        ASSERTX(RTN_IsSafeForProbedReplacement(rtn));
        RTN_ReplaceSignatureProbed(
                rtn, AFUNPTR(TestIargPreserveReplacement),
                IARG_PROTOTYPE, proto,
                IARG_CONTEXT,
                IARG_ORIG_FUNCPTR,
                IARG_PRESERVE, &regsFP,
                IARG_END);
        PROTO_Free( proto );
    }


    rtn = RTN_FindByName(img, "TestIargPreserveInReplacement1");

    if (RTN_Valid(rtn))
    {
        printf ("found TestIargPreserveInReplacement1\n");
        fflush (stdout);
        PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                      "TestIargPreserveInReplacementProto", PIN_PARG_END() );
        ASSERTX(RTN_IsSafeForProbedReplacement(rtn));
        RTN_ReplaceSignatureProbed(
                rtn, AFUNPTR(TestIargPreserveReplacement1),
                IARG_PROTOTYPE, proto,
                IARG_CONTEXT,
                IARG_ORIG_FUNCPTR,
                IARG_END);
        PROTO_Free( proto );
    }

    rtn = RTN_FindByName(img, "TestIargPreserveInProbed");

    if (RTN_Valid(rtn))
    {
        printf ("found TestIargPreserveInProbed\n");
        REGSET regsFP;
        REGSET_Clear(regsFP);
        REGSET_Insert (regsFP, REG_X87);
        ASSERTX(RTN_IsSafeForProbedInsertion(rtn));
        PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                      "TestIargPreserveInReplacementProto", PIN_PARG_END() );
        RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR( TestIargPreserveProbedBefore ),
                             IARG_PROTOTYPE, proto,
                             IARG_CONTEXT,
                             IARG_PRESERVE, &regsFP,
                             IARG_END);
        PROTO_Free( proto );
    }


    rtn = RTN_FindByName(img, "TestIargPreserveInProbed1");

    if (RTN_Valid(rtn))
    {
        printf ("found TestIargPreserveInProbed\n");
        ASSERTX(RTN_IsSafeForProbedInsertion(rtn));
        PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                      "TestIargPreserveInReplacementProto", PIN_PARG_END() );
        RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR( TestIargPreserveProbedBefore1 ),
                             IARG_PROTOTYPE, proto,
                             IARG_CONTEXT,
                             IARG_END);
        PROTO_Free( proto );
    }

}

class FINI 
{
public:
    ~FINI()
    {
        if (testNum != NUM_TESTS)
        {
            printf ("***Error not all expected tests ran testNum %d\n", testNum);
            exit (-1);
        }
    }
};

FINI globFini;

int main(int argc, char *argv[])
{

    PIN_Init(argc, argv);

    PIN_InitSymbols();

    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Never returns
    PIN_StartProgramProbed();
    
    return 0;
}

