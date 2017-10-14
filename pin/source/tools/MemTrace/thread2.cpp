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
#include <assert.h>
#include <stdio.h>
#include "../threadlib/threadlib.h"


#if defined(TARGET_WINDOWS)
#include <windows.h>
#define EXPORT_CSYM extern "C" __declspec( dllexport )

#else
#define EXPORT_CSYM extern "C" 

#endif

int a[100000];
int n = 10;
long numthreads = 16;
EXPORT_CSYM unsigned int numthreadsStarted = 0;

extern "C" void AtomicIncrement();

EXPORT_CSYM void  DoWork()
{
    int i,j;
    
    for (j = 0; j < 1000; j++)
    {
        for (i = 0; i < n; i++)
        {
            a[i] = 1;
        }
    }
}


EXPORT_CSYM void WaitForAllThreadsStarted()
{
    AtomicIncrement(); // atomically increments numthreadsStarted 
    while (numthreadsStarted != numthreads)
    {
    }
}

EXPORT_CSYM void * ThreadStart(void * arg)
{
    int i;
    // no thread starts the work loop until all threads are in the ThreadStart function
    WaitForAllThreadsStarted();
    for (i = 0; i< 100; i++)
    {
        DoWork();
    }
    return (NULL);
}



THREAD_HANDLE threads[MAXTHREADS];

EXPORT_CSYM int main(int argc, char *argv[])
{
    int i,j;

    for (i = 0; i < numthreads; i++)
    {
        CreateOneThread(&threads[i], ThreadStart, 0);
    }

    for (i = 0; i < numthreads; i++)
    {
        BOOL success;
        success = JoinOneThread (threads[i]);
    }

    return 0;
}
