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

#if defined (TARGET_WINDOWS)
#include <windows.h>

void WindowsOpen(char* filename)
{
	HMODULE hdll = LoadLibrary(filename);
    if(hdll == NULL)
    {
		fprintf(stderr, "Failed to load: %s\n", filename);
		fflush(stderr);
        exit(2);
    } 
    FreeLibrary(hdll);
}

#else /* Not TARGET_WINDOWS */
#include <dlfcn.h>

void UnixOpen(char* filename)
{
    void* dlh = dlopen(filename, RTLD_LAZY);
    if( !dlh ) {
        fprintf(stderr, " Failed to load: %s because: %s", filename, dlerror());
        exit(2);
    }
    else
    {
       fprintf(stderr, " Loaded: %s", filename);
    }
    dlclose(dlh);
} 

#endif /* TARGET_WINDOWS */

int main(int argc, char** argv)
{
	if(argc<1) 
    {
        fprintf(stderr, "No image name to load has been supplied" );
		fflush(stderr);
        return 1;
    }

#ifdef TARGET_WINDOWS
	WindowsOpen(argv[1]);
#else
	UnixOpen(argv[1]);
#endif /* TARGET_WINDOWS */
	
    return 0;
}
