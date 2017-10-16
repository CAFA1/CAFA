#include "pin.H"

#include <cassert>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stack>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <stdint.h>
#include <cstdlib>
#include <algorithm> 
#include <list>
#include <iomanip>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pin_frame.h"
#include "pin_trace.h"
#include "reg_mapping_pin.h"
#include "cache.h"
//#include <capstone/capstone.h>

/* The new trace container format */
#include "trace.container.hpp"

//#include "pin_frame.cpp"
//#include "pin_trace.cpp"

#include "pivot.h"

#include "pin_taint.h"
#include "pin_misc.h"

using namespace pintrace;
using namespace SerializedTrace;

const ADDRINT ehandler_fs_offset = 0;
const ADDRINT ehandler_nptr_offset = 0;
const ADDRINT ehandler_handler_offset = 4;
const ADDRINT ehandler_invalid_ptr = 0xFFFFFFFF;
const ADDRINT ehandler_size = 8;
/** The offset esp has from when the exception is initially handled to
    when the handler is called. */
const ADDRINT ehandler_esp_offset = 0xe0;

const int maxSehLength = 10;

#ifdef _WIN32

const char* const windowsDll = "kernel32.dll";
const char* const wsDll = "WS2_32.dll";

const int callbackNum = 5;

const unsigned int accessViolation = 0xc0000005;

namespace WINDOWS {
#include "Winsock2.h"
#include "Windows.h"
}
#endif

/* Environment variables on windows
 * 
 * For a program that uses getenv, Windows does the following:
 *
 * 1. Call GetEnvironmentStringsW and set up an environment table.
 * 2. If using main (rather than wmain), WideCharToMultiByte is used
 * to convert to a multibyte environment table.
 * 
 * WideCharToMultiByte is implemented using a conversion table; we
 * don't handle control-flow taint, and thus we cannot really handle
 * tainting of environment variables :-/
 */

/* Networking on windows
 * 
 * Winsock appears to communicate with a windows subsystem using a
 * lightweight procedure calling interface, e.g., something we don't
 * want to parse.  So, we catch sockets() by instrumenting the socket
 * call itself.
 */

//
// CONFIGURATION
//

// Note: since we only flush the buffer once per basic block, the number
// of instructions per block should never exceed BUFFER_SIZE.
// TODO: See if there's some way to overcome this limitation, if
// necessary.
#define BUFFER_SIZE 10240

// Leave this much extra room in the frame buffer, for some unexpected
// frames.
#define FUDGE 5

// Add a keyframe every KEYFRAME_FREQ instructions.
#define KEYFRAME_FREQ 10240

// Use value caching.
#define USE_CACHING

// Use faster functions to append to the value buffer, where possible.
//#define USE_FASTPATH

#ifdef USE_FASTPATH
#define _FASTPATH true
#else
#define _FASTPATH false
#endif

/** Set to 1 to enable lock debug information */
#ifndef DEBUG_LOCK
#define DEBUG_LOCK 0
#endif
//1208/////////////////////////////////////////////////////
int mylog(char * log);
char CoverageModule[0x20];

//ofstream fpaddrs;
ADDRINT  DllbaseAddress=0;

uint32_t  g_TaintAsistBuff[5120];
uint32_t g_tsbufidx;
uint64_t g_Execlimit;
//9 20 liu
time_t start_time ;
time_t g_time;
int cleanup_flag=0;
//liu 1012
bool crc32_Instrumentation_On = false;

//liu global 911

#define TraceFile ((thread_info1[(PIN_ThreadId()<0)? 0 :PIN_ThreadId()].trace_file))
///////////////

KNOB<string> KnobOut(KNOB_MODE_WRITEONCE, "pintool",
                     "o", "out.bpt",
                     "Trace file to output to.");
//1208//////////////////////////////////////
KNOB<string> KnobCoverage(KNOB_MODE_WRITEONCE, "pintool",
                     "c", "docreader.dll",
                     "Coverage fraction module.");
///////////////////////////////
//9 20 liu
KNOB<int> KnobTime(KNOB_MODE_WRITEONCE, "pintool",
                            "time-limit", "5",
                            "time out seconds.");

KNOB<int> KnobTrigAddr(KNOB_MODE_WRITEONCE, "pintool",
                       "trig_addr", "",
                       "Address of trigger point. No logging will occur until execution reaches this address.");

KNOB<string> KnobTrigModule(KNOB_MODE_WRITEONCE, "pintool",
                            "trig_mod", "",
                            "Module that trigger point is in.");

KNOB<int> KnobTrigCount(KNOB_MODE_WRITEONCE, "pintool",
                        "trig_count", "0",
                        "Number of times trigger will be executed before activating.");

//
// NOTE: This limit is not a hard limit; the generator only stops logging
// during buffer flushes, so the actual number of instructions logged
// might exceed log_limit, but at the most by BUFFER_SIZE.
// Also note that the limit is in terms of the number of _instructions_,
// not frames; things like keyframes, LoadModuleFrames, etc. are not
// included in the count.
//
KNOB<uint64_t> KnobLogLimit(KNOB_MODE_WRITEONCE, "pintool",
                            "log-limit", "0",
                            "Number of instructions to limit logging to.");
//liu 925
KNOB<uint64_t> KnobChksmDegree(KNOB_MODE_WRITEONCE, "pintool",
                            "check", "10",
                            "Number of checksum reference.");
//1208//////////////////////////////////
KNOB<uint64_t> KnobInsLimit(KNOB_MODE_WRITEONCE, "pintool",
                            "ins-limit", "0",
                            "Number of instructions to excution.");
///////////
KNOB<bool> LogAllSyscalls(KNOB_MODE_WRITEONCE, "pintool",
                          "log-syscalls", "false",
                          "Log system calls (even those unrelated to taint)");

KNOB<bool> KnobTaintTracking(KNOB_MODE_WRITEONCE, "pintool",
                             "taint-track", "true", 
                             "Enable taint tracking");

KNOB<bool> LogAllAfterTaint(KNOB_MODE_WRITEONCE, "pintool",
                            "logall-after", "false", 
                            "Log all (even untainted) instructions after the first tainted instruction");

KNOB<bool> LogAllBeforeTaint(KNOB_MODE_WRITEONCE, "pintool",
                             "logall-before", "false", 
                             "Log all (even untainted) instructions before and after the first tainted instruction");

// This option logs one instruction.  It then generates a fake
// standard frame to include operands after the instruction executed.
KNOB<bool> LogOneAfter(KNOB_MODE_WRITEONCE, "pintool",
                       "logone-after", "false",
                       "Log the first instruction outside of the log range (taint-start/end), and then exit.");
//1208////////////////////////////////////
KNOB<int> TaintedOffsets(KNOB_MODE_APPEND, "pintool",
"taint-offsets", "",
"Consider the given offsets as being tainted");

KNOB<bool> LogKeyFrames(KNOB_MODE_WRITEONCE, "pintool",
                        "log-key-frames", "false",
                        "Periodically output key frames containing important program values");

KNOB<string> TaintedFiles(KNOB_MODE_APPEND, "pintool",
                          "taint-files", "", 
                          "Consider the given files as being tainted");

KNOB<bool> TaintedArgs(KNOB_MODE_WRITEONCE, "pintool",
                       "taint-args", "false", 
                       "Command-line arguments will be considered tainted");

KNOB<bool> TaintedStdin(KNOB_MODE_WRITEONCE, "pintool",
                        "taint-stdin", "false", 
                        "Everything read from stdin will be considered tainted");

KNOB<bool> TaintedNetwork(KNOB_MODE_WRITEONCE, "pintool",
                          "taint-net", "false", 
                          "Everything read from network sockets will be considered tainted");

KNOB<bool> TaintedIndices(KNOB_MODE_WRITEONCE, "pintool",
                          "taint-indices", "false", 
                          "Values loaded with tainted memory indices will be considered tainted");

// FIXME: we should be able to specify more refined tainted 
// sources, e.g., that only the 5th argument should be considered
// tainted
KNOB<string> TaintedEnv(KNOB_MODE_APPEND, "pintool",
                        "taint-env", "", 
                        "Environment variables to be considered tainted");

KNOB<uint32_t> TaintStart(KNOB_MODE_WRITEONCE, "pintool",
                          "taint-start", "0x0", 
                          "All logged instructions will have higher addresses");

KNOB<uint32_t> TaintEnd(KNOB_MODE_WRITEONCE, "pintool",
                        "taint-end", "0xffffffff", 
                        "All logged instructions will have lower addresses");

KNOB<string> FollowProgs(KNOB_MODE_APPEND, "pintool",
                         "follow-progs", "", 
                         "Follow the given program names if they are exec'd");

KNOB<string> PivotFile(KNOB_MODE_WRITEONCE, "pintool",
                       "pivots-file", "",
                       "Load file of pivot gadgets");

KNOB<bool> SEHMode(KNOB_MODE_WRITEONCE, "pintool",
                   "seh-mode", "false",
                   "Record an SEH exploits");

KNOB<int> CheckPointFreq(KNOB_MODE_WRITEONCE, "pintool",
                         "freq", "10000",
                         "Report value of eip every n instructions.");

KNOB<int> CacheLimit(KNOB_MODE_WRITEONCE, "pintool",
                     "cache-limit", "500000000",
                     "Code-cache size limit (bytes)");

KNOB<int> SkipTaints(KNOB_MODE_WRITEONCE, "pintool",
                     "skip-taints", "0",
                     "Skip this many taint introductions");

struct FrameBuf {
    uint32_t addr;
    uint32_t tid;
    uint32_t insn_length;

    // The raw instruction bytes will be stored as 16 bytes placed over 4
    // integers. The conversion is equivalent to the casting of a char[16]
    // to a uint32_t[4].
    // NOTE: This assumes that MAX_INSN_BYTES == 16!!!
    uint32_t rawbytes0;
    uint32_t rawbytes1;
    uint32_t rawbytes2;
    uint32_t rawbytes3;

    uint32_t values_count;
    ValSpecRec valspecs[MAX_VALUES_COUNT];

};

/**
 * Temporary structure used during instrumentation.
 */
typedef struct TempOps_s {
    uint32_t reg;
    RegMem_t type;
    uint32_t taint;
} TempOps_t;

/**
 * Posible ways of passing a register to an analysis function
 */
enum RPassType { P_VALUE, P_REF, P_CONTEXT, P_FPX87 };

/**
 * Given a register, decide how to pass it.
 */
static RPassType howPass(REG r) {

    if(REG_is_fr_for_get_context(r))
      return P_CONTEXT;
    
    /* XMM and floating point registers can be passed by reference */
    if (REG_is_xmm(r) || REG_is_ymm(r) || REG_is_mm(r))
        return P_REF;

    if(REG_is_fr_or_x87(r))
        return P_FPX87;
    
    // For now, let's just use context
    return P_CONTEXT;
}






VOID InitLogs(THREADID tid)
{
    char filename[32];
    stringstream file_logs;
    file_logs<< KnobOut.Value() << "-" <<tid<< "logs.txt";
    
    strcpy(filename,file_logs.str().c_str());
    thread_info1[tid].trace_file.open(filename,ios::app|ios::out);
    thread_info1[tid].trace_file.setf (ios::showbase);
 
    thread_info1[tid].trace_file << "[DBG] " << "thread begin" << endl;
}


//liu func end 911
/**
 * Avoiding logging some addresses.
 */
static bool dontLog(ADDRINT addr) {

    IMG i = IMG_FindByAddress(addr);
    if (IMG_Valid(i)) {

        char tempbuf[BUFSIZE];
        char *tok = NULL;
        char *lasttok = NULL;
    
        // Fill up the temporary buffer
        strncpy(tempbuf, IMG_Name(i).c_str(), BUFSIZE);
    
        // We don't need a lock, since this is an instrumentation function (strtok is not re-entrant)
        strtok(tempbuf, "\\");
    
        while ((tok = strtok(NULL, "\\")) != NULL) {
            // Just keep parsing...
            lasttok = tok;
        }
    
        if (lasttok) {
            if (lasttok == string("uxtheme.dll")) {
                return true;
            }
        }
    }

    return false;
}



/**
 * This type preserves state between a system call entry and exit.
 */
typedef struct SyscallInfo_s {

    /** Frame for system call */
    frame sf;

    /** State shared between taintIntro and taintStart */
    uint32_t state;
} SyscallInfo_t;

/**
 * This type preserves state between a recv() call and return
 */
typedef struct RecvInfo_s {
    /** Fd */
    uint32_t fd;

    /** The address */
    void* addr;

    /** Bytes written ptr. */
    uint32_t *bytesOut;
} RecvInfo_t;

/**
 * Thread local information
 */

typedef struct ThreadInfo_s {
    // Stack keeping track of system calls
    // Needed because windows system calls can be nested!
    std::stack<SyscallInfo_t> scStack;
    std::stack<RecvInfo_t> recvStack;
    context delta;
} ThreadInfo_t;

uint32_t g_counter = 0;

//TraceWriter *g_tw;
//TraceContainerWriter *g_twnew;
//liu 11 9
//char buf_file_assist[50];


// A taint tracker
TaintTracker * tracker;

FrameBuf g_buffer[BUFFER_SIZE];
uint32_t g_bufidx;

// Counter to keep track of when we should add a keyframe.
uint32_t g_kfcount;

// Caches.
//RegCache g_regcache;
//MemCache g_memcache;

// Profiling timer.
clock_t g_timer;

// True if logging is activated.
// Logging should be activated if it is possible for some instruction
// to be logged.  This could happen because 1) we are logging all
// instructions, or 2) taint is introduced, and so the instruction
// could be tainted.
bool g_active;

// Number of instructions logged so far.
uint64_t g_logcount;

// Number of instructions to limit logging to.
uint64_t g_loglimit;

// True if a trigger was specified.
bool g_usetrigger;

// Activate taint analysis
// bool t_active;

// Whether taint has been introduced
bool g_taint_introduced;

// True if the trigger address was resolved.
bool g_trig_resolved;

uint32_t g_trig_addr;

// We use a signed integer because sometimes the countdown will be
// decremented past zero.
int g_trig_countdown;

// Name of our thread/process
char g_threadname[BUFFER_SIZE] = "";


// An environment to keep all the values
ValSpecRec values[MAX_VALUES_COUNT];

// Address ranges
uint32_t start_addr, end_addr;

// Pivot set
pivot_set ps;

// Exit after the next instruction
bool g_exit_next;

// Prototypes.
VOID Cleanup();

// Key for thread local system call stack
static TLS_KEY tl_key;


// Start of functions.

VOID ModLoad(IMG i, void*);

// Get Thread Info
ThreadInfo_t* GetThreadInfo(void) {
    ThreadInfo_t* ti;

    ti = static_cast<ThreadInfo_t*> (PIN_GetThreadData(tl_key, PIN_ThreadId()));
    assert(ti);
    return ti;
}

// Create a new thread information block for the current thread
ThreadInfo_t* NewThreadInfo(void) {
    ThreadInfo_t* ti = NULL;

    ti = new ThreadInfo_t;
    assert(ti);

    PIN_SetThreadData(tl_key, ti, PIN_ThreadId());

    return ti;
}

/** Given a REG, return the number of bits in the reg */
static uint32_t GetBitsOfReg(REG r) {
    if (REG_is_gr8(r)) return 8;
    if (REG_is_gr16(r)) return 16;
    if (REG_is_gr32(r)) return 32;
    if (REG_is_gr64(r)) return 64;

    /* REG_is_fr_or_x87 returns true on XMM registers and other
       non-x87 regs, so we can't use that. */
    if (REG_ST_BASE <= r && r <= REG_ST_LAST) return 80;

    string s = REG_StringShort(r);

    switch (r) {
    case REG_SEG_CS:
    case REG_SEG_DS:
    case REG_SEG_ES:
    case REG_SEG_FS:
    case REG_SEG_GS:
    case REG_SEG_SS:
        return 16;
        break;

    case REG_INST_PTR:
    case REG_EFLAGS:
    case REG_MXCSR:
        return 32;
        break;

    case REG_MM0:
    case REG_MM1:
    case REG_MM2:
    case REG_MM3:
    case REG_MM4:
    case REG_MM5:
    case REG_MM6:
    case REG_MM7:
        return 64;
        break;

    case REG_XMM0:
    case REG_XMM1:
    case REG_XMM2:
    case REG_XMM3:
    case REG_XMM4:
    case REG_XMM5:
    case REG_XMM6:
    case REG_XMM7:
        return 128;
        break;

    case REG_YMM0:
    case REG_YMM1:
    case REG_YMM2:
    case REG_YMM3:
    case REG_YMM4:
    case REG_YMM5:
    case REG_YMM6:
    case REG_YMM7:
        return 256;
        break;

    default:
        break;
    }

    // Otherwise, exit because we don't know what's up
    cerr << "Warning: Unknown register size of register " << REG_StringShort(r) << endl;
    assert(false);
    return -1;
}

static uint32_t GetByteSize(RegMem_t vtype) {
    return (vtype.size / 8);
}

static uint32_t GetBitSize(RegMem_t type) {
    return type.size;
}

void LLOG(const char *str) {
#if DEBUG_LOCK
    LOG(str);
#else
    /* Disabled */
#endif
}

ADDRINT CheckTrigger()
{
    return --g_trig_countdown <= 0;
}

/** Reinstrument all images. XXX: Remove me. */
VOID InstrumentIMG() {
    PIN_LockClient();
    for (IMG i = APP_ImgHead(); IMG_Valid(i); i = IMG_Next(i)) {
        ModLoad(i, (void*)1);
    }
    PIN_UnlockClient();
}

VOID Activate(CONTEXT *ctx)
{
    cerr << "Activating logging" << endl;
    g_active = true;
    PIN_RemoveInstrumentation();
    PIN_ExecuteAt(ctx);
}

/** Activate taint analysis.

    Note: It's important to NOT hold locks when calling this function.
    PIN_RemoveInstrumentation obtains the VM lock, which is only possible
    when no analysis functions/etc are executing.  If one is waiting for
    one of our locks, this will cause a deadlock.  
*/
VOID TActivate()
{
    cerr << "Activating taint analysis " << endl;
    g_active = true; /* Any instruction could be logged because taint is
                        introduced. */
    g_taint_introduced = true; /* Taint is definitely introduced now. */
    PIN_RemoveInstrumentation();
    //InstrumentIMG();
}

//
// Returns true if the buffer index with count added to it exceeds the
// maximum size of the buffer.
//
ADDRINT CheckBuffer(UINT32 count)
{
  return (g_bufidx + count) >= BUFFER_SIZE - FUDGE;
}

ADDRINT CheckBufferEx(BOOL cond, UINT32 count, UINT32 count2)
{
  return cond && ((g_bufidx + count + count2) >= BUFFER_SIZE - FUDGE);
}

// Callers must ensure mutual exclusion
VOID FlushInstructions()
{

    for(uint32_t i = 0; i < g_bufidx; i++) {

        frame fnew;
        fnew.mutable_std_frame()->set_address(g_buffer[i].addr);
        fnew.mutable_std_frame()->set_thread_id(g_buffer[i].tid);
        /* Ew. */
        fnew.mutable_std_frame()->set_rawbytes((void*)(&(g_buffer[i].rawbytes0)), g_buffer[i].insn_length);

        /* Add operands */

        // Go through each value and remove the ones that are cached.

        /* The operand_list is a required field, so we must access it
           even if there are no operands or protobuffers will complain to
           us. */
        fnew.mutable_std_frame()->mutable_operand_list();

        for (uint32_t j = 0; j < g_buffer[i].values_count; j++) {

            ValSpecRec &v = g_buffer[i].valspecs[j];

            operand_info *o = fnew.mutable_std_frame()->mutable_operand_list()->add_elem();
            o->set_bit_length(GetBitSize(v.type));
            o->mutable_operand_usage()->set_read(v.usage & RD);
            o->mutable_operand_usage()->set_written(v.usage & WR);
            /* XXX: Implement index and base */
            o->mutable_operand_usage()->set_index(false);
            o->mutable_operand_usage()->set_base(false);

            switch (v.taint) {
            case 0:
                o->mutable_taint_info()->set_no_taint(true);
                break;
            case -1:
                o->mutable_taint_info()->set_taint_multiple(true);
                break;
            default:
                o->mutable_taint_info()->set_taint_id(v.taint);
                break;
            }

            if (tracker->isMem(v.type)) {
                o->mutable_operand_info_specific()->mutable_mem_operand()->set_address(v.loc);

            } else {
                string t = pin_register_name((REG)v.loc);
                if (t == "Unknown") {
                    t = string("Unknown ") + REG_StringShort((REG)v.loc);
                }
                o->mutable_operand_info_specific()->mutable_reg_operand()->set_name(t);
            }

            o->set_value(&(v.value), GetByteSize(v.type));

            // We're in trouble if we don't know the type.
            if(v.type.type != REGISTER && v.type.type != MEM) {
                cerr << "v.type = " << v.type.type << endl;                
                assert(false);
            }
        }

        //g_twnew->add(fnew);
    }

    // Update counts.
    g_logcount += g_bufidx;
    g_kfcount += g_bufidx;

    g_bufidx = 0;

}

/* Add a PIN register to a value list. Helper function for FlushBuffer */
VOID AddRegister(tagged_value_list *tol, const CONTEXT *ctx, REG r, THREADID threadid) {
    tol->mutable_value_source_tag()->set_thread_id(threadid);
    value_info *v = tol->mutable_value_list()->add_elem();
    v->mutable_operand_info_specific()->mutable_reg_operand()->set_name(REG_StringShort(r));
      size_t s_bytes = GetBitsOfReg(r) / 8;
      v->set_bit_length(s_bytes * 8);

    /* Make sure this register even fits in the context.  PIN would
       probably throw an error, but it's good to be paranoid. */
    assert (s_bytes <= sizeof(ADDRINT));
    ADDRINT regv = PIN_GetContextReg(ctx, r);
    v->set_value((void*)(&regv), s_bytes);
    //std::copy((uint8_t*) (&regv), ((uint8_t*) (&regv)) + s_bytes, v->
}

//
// Writes all instructions stored in the buffer to disk, and resets the
// buffer index to 0. Also checks to see if we need to insert a
// keyframe. If so, inserts the keyframe using the data in the supplied
// context.
//
VOID FlushBuffer(BOOL addKeyframe, const CONTEXT *ctx, THREADID threadid, BOOL needlock)
{

    

}



/** Wrapper for accept */
uint32_t OpenWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, char* s, int flags, mode_t mode) {

    //cerr << "OpenWrapper" << endl;

    uint32_t ret;

    PIN_CallApplicationFunction(ctx, tid,
                                CALLINGSTD_STDCALL, fp,
                                PIN_PARG(uint32_t), &ret,
                                PIN_PARG(char*), s,
                                PIN_PARG(int), flags,
                                PIN_PARG(mode_t), mode,
                                PIN_PARG_END());

    GetLock(&lock, tid+1);
    tracker->OpenHelper(ret,s);
    ReleaseLock(&lock);

    return ret;
			      
}
/*

uint32_t WSAConnectWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, uint32_t s, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7) {

    cerr << "WSAConnectWrapper" << endl;

    uint32_t ret;

    cerr << "Connect to socket " << s << endl;

    PIN_CallApplicationFunction(ctx, tid,
                                CALLINGSTD_STDCALL, fp,
                                PIN_PARG(uint32_t), &ret,
                                PIN_PARG(uint32_t), s,
                                PIN_PARG(void*), arg2,
                                PIN_PARG(void*), arg3,
                                PIN_PARG(void*), arg4,
                                PIN_PARG(void*), arg5,
                                PIN_PARG(void*), arg6,
                                PIN_PARG(void*), arg7,
                                PIN_PARG_END());

    GetLock(&lock, tid+1);
    if (ret != SOCKET_ERROR) {
        tracker->acceptHelper(s);
    } else {
        cerr << "WSAConnect error " << ret << endl;
    }
    ReleaseLock(&lock);

    return ret;
			      
}


uint32_t ConnectWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, uint32_t s, void *arg2, void *arg3) {

    cerr << "ConnectWrapper" << endl;

    uint32_t ret;

    cerr << "Connect to socket " << s << endl;

    PIN_CallApplicationFunction(ctx, tid,
                                CALLINGSTD_STDCALL, fp,
                                PIN_PARG(uint32_t), &ret,
                                PIN_PARG(uint32_t), s,
                                PIN_PARG(void*), arg2,
                                PIN_PARG(void*), arg3,
                                PIN_PARG_END());

    GetLock(&lock, tid+1);
    //  if (ret != SOCKET_ERROR) {
    // Non-blocking sockets will return an "error".  However, we can't
    // call GetLastError to find out what the root problem is,
    // so... we'll just assume the connection was successful.
    tracker->acceptHelper(s);
 
    // } else {
    //    cerr << "connect error " << ret << endl;
    //  }
    ReleaseLock(&lock);

    return ret;
			      
}

void BeforeRecv(THREADID tid, uint32_t s, char* buf) {

    RecvInfo_t r;

    r.fd = s;
    r.addr = buf;
    r.bytesOut = NULL;

    ThreadInfo_t *ti = GetThreadInfo();

    ti->recvStack.push(r);
}

void WSABeforeRecv(THREADID tid, uint32_t s, WINDOWS::LPWSABUF bufs, WINDOWS::LPDWORD bytesOut) {

    RecvInfo_t r;

    r.fd = s;
    r.addr = bufs[0].buf;
    r.bytesOut = (uint32_t*) bytesOut;

    ThreadInfo_t *ti = GetThreadInfo();

    ti->recvStack.push(r);
}

void AfterRecv(THREADID tid, int ret, char *f) {
    cerr << "afterrecv called by " << f << endl;
    ThreadInfo_t *ti = GetThreadInfo();
    uint32_t len = 0;

    if (ti->recvStack.empty()) {
        cerr << "WARNING: Stack empty in AfterRecv(). Thread " << tid << endl;
    } else {
  
        RecvInfo_t ri = ti->recvStack.top();
        ti->recvStack.pop();
    
        if (ret != SOCKET_ERROR) {
            GetLock(&lock, tid+1);
            //cerr << "fd: " << ri.fd << endl;

            uint32_t numbytes = 0;
            if (ri.bytesOut) {
                numbytes = *(ri.bytesOut);
            } else {
                numbytes = ret;
            }

            FrameOption_t fo = tracker->recvHelper(ri.fd, ri.addr, numbytes);
            ReleaseLock(&lock);
      
            if (fo.b) {
	
                if (!g_taint_introduced) {
                    TActivate();
                }
	
                GetLock(&lock, tid+1);
                g_twnew->add(fo.f);
                ReleaseLock(&lock);
            }
        } else {
            cerr << "recv() error " << endl;
        }
    }
}



void* GetEnvWWrap(CONTEXT *ctx, AFUNPTR fp, THREADID tid) {
    void *ret = NULL;

    

    PIN_CallApplicationFunction(ctx, tid,
                                CALLINGSTD_STDCALL, fp,
                                PIN_PARG(uint32_t), &ret,
                                PIN_PARG_END());

    LLOG("Getting lock in callback\n");

    GetLock(&lock, tid+1);
    LLOG("Got callback lock\n");

    std::vector<frame> frms = tracker->taintEnv(NULL, (wchar_t*) ret);
    g_twnew->add<std::vector<frame> > (frms);

    ReleaseLock(&lock);
    LLOG("Releasing callback lock\n");

    return ret;
}


void* GetEnvAWrap(CONTEXT *ctx, AFUNPTR fp, THREADID tid) {
    void *ret = NULL;

    cerr << "In a wrap " << endl;

   

    PIN_CallApplicationFunction(ctx, tid,
                                CALLINGSTD_STDCALL, fp,
                                PIN_PARG(uint32_t), &ret,
                                PIN_PARG_END());

    LLOG("Getting lock in callback\n");

    GetLock(&lock, tid+1);
    LLOG("Got callback lock\n");

    std::vector<frame> frms = tracker->taintEnv((char*) ret, NULL);
    g_twnew->add<std::vector<frame> > (frms);

    ReleaseLock(&lock);
    LLOG("Releasing callback lock\n");

    return ret;
}
*/


/* This analysis function is called after the target instruction is
 * executed when using -logone-after. It transfer control back to the
 * same instruction to log its operands after execution. */
VOID PostInstruction(ADDRINT addr, CONTEXT *ctx) {
    g_exit_next = true;
    PIN_SetContextReg(ctx, REG_INST_PTR, addr);
    PIN_ExecuteAt(ctx);
}

VOID AppendBuffer(ADDRINT addr,
                  THREADID tid,
                  CONTEXT *ctx,
                  BOOL isBranch,
                  UINT32 insn_length,

                  UINT32 rawbytes0,
                  UINT32 rawbytes1,
                  UINT32 rawbytes2,
                  UINT32 rawbytes3,
                   
                  /* Type contains the type of the operand. Location
                   * specifies the base address for memory operands.
                   * For registers, this holds the ID of the
                   * register.  Value is used to pass register values
                   * by reference.  For memory operands, it holds the
                   * byte offset into memory.  For instance, a 32-bit
                   * memory operand is broken into four 8-bit operands
                   * with the same address (specified in location),
                   * but with different offsets (0, 1, 2, 3) in
                   * value.  Usage specifies how the operand is used
                   * (read, write, etc.) */                   

                  UINT32 values_count,
                  ...
                  )
{
    va_list va;
    va_start(va, values_count);

    static int firstTaint = true;
    static int firstLogged = true;
    REG r;

    //LOG("APPEND: " + hexstr(addr) + "\n");

    /* BUILD_VAL touches values, so we need the lock early. */

    /* Periodically report eip. */
    if ((g_counter++ % CheckPointFreq.Value()) == 0) {
        // PIN_LockClient();
        // IMG i = IMG_FindByAddress(addr);
        // PIN_UnlockClient();
        // cerr << "Checkpoint: Executing code at " << addr;
        // if (IMG_Valid(i)) {
        //   cerr << " (" << IMG_Name(i) << ")";
        // } 
        //cerr << " thread " << tid
           //  << "; " << g_counter << " instructions" << endl
           //  << "Code cache size is " << CODECACHE_CodeMemUsed() << endl
           //  << "Code cache limit is " << CODECACHE_CacheSizeLimit() << endl;
    }
    //9 20 liu
    time_t tmp = time(0);
    tmp =  tmp - start_time;
    if ( tmp > g_time)
    {
        cout << "time out!"<<endl;
        
        Cleanup();
        
    }



	//1208//////////////////////////////////////////////
	if(g_Execlimit!=0 && g_counter>g_Execlimit )
	{
		cerr << "Logged required number:"<<g_Execlimit<<"  "<<g_counter<<" instructions, quitting.\n";
		
        Cleanup();
        
       

	}
	///////////////////////

    LLOG("big thing\n");
  
    //GetLock(&lock, tid+1);
  
    LLOG("got big thing\n");

    for (unsigned int i = 0; i < values_count; i++) {
        values[i].type.type = (RegMemEnum_t)va_arg(va, uint32_t);
        assert(valid_regmem_type(values[i].type));
        
        values[i].type.size = va_arg(va, uint32_t);
        values[i].loc = va_arg(va, uint32_t);
        values[i].value.dword[0] = va_arg(va, uint32_t);			
        values[i].usage = va_arg(va, uint32_t);				
        if (tracker->isMem(values[i].type)) {
            /* Add memory byte offset */					
            values[i].loc += values[i].value.dword[0];			
        } 		    
    }

    /* Perform taint propagation and checking */

    bool abort = false;
    bool log_addr =
        ((start_addr <= addr) && (addr <= end_addr)) || LogOneAfter.Value();
    bool log_all =
        ((LogAllAfterTaint.Value() && !firstTaint)
         || LogAllBeforeTaint.Value());
    uint32_t pretaint[MAX_VALUES_COUNT];
    LEVEL_VM::PIN_REGISTER *pr = NULL;
    ThreadInfo_t *ti = NULL;

    ti = GetThreadInfo();

    tracker->setCount(values_count);

    bool has_taint = tracker->hasTaint(ti->delta);

    if ((log_all || has_taint) && log_addr) {

        /* This instruction is tainted, or we're logging all
         * instructions */

        if (firstLogged) {
            cerr << "First logged instruction" << endl;
            firstLogged = false;
        }
     
        if (has_taint && firstTaint) {
            cerr << "First tainted instruction" << endl;
            LOG("First tainted instruction.\n");
            firstTaint = false;
        }

        // Mark everything as untainted
        for (uint32_t i = 0 ; i < values_count ; i++) 
            values[i].taint = 0;
     
        // Set taint values from taint context
        tracker->setTaintContext(ti->delta);

        // Record pretaint (this goes in the log)
        for (uint32_t i = 0 ; i < values_count ; i++) 
            pretaint[i] = values[i].taint;

        // Did this instruction propagate taint?
        //propagated_taint = tracker->propagatedTaint(isBranch);
      
        if (!isBranch)
            tracker->taintPropagation(ti->delta);

        // Taint checking
        abort = !tracker->taintChecking();
         
        //} FIXME: it there a case where the instruction contains taint
        //  but we do not need to log it?
        //if (log || (has_taint && propagated_taint)) {
   
        //cerr << "Logging instruction " << rawbytes0 << " " << rawbytes1 << endl;

        // Now, fill in the buffer with information

	assert (g_bufidx < BUFFER_SIZE);
      
        g_buffer[g_bufidx].addr = addr;
        g_buffer[g_bufidx].tid = tid;
        g_buffer[g_bufidx].insn_length = insn_length;

        g_buffer[g_bufidx].rawbytes0 = rawbytes0;
        g_buffer[g_bufidx].rawbytes1 = rawbytes1;
        g_buffer[g_bufidx].rawbytes2 = rawbytes2;
        g_buffer[g_bufidx].rawbytes3 = rawbytes3;

        // tracker->printRegs();

        g_buffer[g_bufidx].values_count = values_count;
  
        //g_buffer[g_bufidx].valspecs[i].taint = values[i].taint;             

        // Values for floating point operations
        bool got_FP_state = false;
        FPSTATE fpState;
        void * fpValue;
        uint32_t s_i;
        
        // Store information to the buffer
        for (unsigned int i = 0; i < values_count; i++) {

            g_buffer[g_bufidx].valspecs[i].type = values[i].type;		
            g_buffer[g_bufidx].valspecs[i].usage = values[i].usage;		
            g_buffer[g_bufidx].valspecs[i].loc = values[i].loc;			
            g_buffer[g_bufidx].valspecs[i].taint = pretaint[i];
     
            if(values[i].type.type == REGISTER) {						
                       /*r = REG_FullRegName((REG) valspec##i##_loc);*/		
                r = (REG)values[i].loc;
       
                /* Find how we should access the register value */             
                switch(howPass(r)) {                                        
                case P_CONTEXT:
                    g_buffer[g_bufidx].valspecs[i].value.dword[0] =
                        PIN_GetContextReg(ctx, r);
                    break;
         
                case P_REF:
                    pr = (LEVEL_VM::PIN_REGISTER*) values[i].value.dword[0];	
                    memcpy(&(g_buffer[g_bufidx].valspecs[i].value),
                           pr,                                               
                           sizeof(LEVEL_VM::PIN_REGISTER));                  
                    break;                                                   

                case P_FPX87:
                    if(!got_FP_state) {
                        /* This is relativly expensive, so only do it once per
                           instruction */
                        PIN_GetContextFPState(ctx, &fpState);
                        got_FP_state = true;
                    }

                    // Figure out which st register we are using
                    s_i = r - REG_ST_BASE;
                    
                    if (s_i > 7) {
                        cerr << "Unknown FP register " << r << " at addr "
                             << addr << endl;
                        assert(false);
                    }
                    
                    fpValue = (void *)&(fpState.fxsave_legacy._sts[s_i]);
                                        
                    memcpy(&(g_buffer[g_bufidx].valspecs[i].value.flt[0]),
                           fpValue,
                           10); // FP are 80 bits = 10 bytes
                    break;
                    
                default:                                                   
                    assert(false);                                           
                    break;                                                   
                }                                                              
            } else if(values[i].type.type == MEM) {
                PIN_SafeCopy((VOID*) &(g_buffer[g_bufidx].valspecs[i].value),	
                             (const VOID *)(g_buffer[g_bufidx].valspecs[i].loc),
                             GetByteSize(values[i].type));
            } else {
                cerr << "Unknown operand type at addr "        
                     << addr << endl;                                          
                assert(false);                                                 
            }
            
            //   cerr << "Building val specs now" << endl;
   
        }

        //   cerr << "... done" << endl;
   
        g_bufidx++;
    }

   //9/13 liu
    /* For a non-SEH exploit, stop if taint checking fails.  In an SEH
       exploit, we may want an exception to trigger (e.g., from
       returning to a bad address). */
        
    if (abort && !SEHMode.Value()) { 
        pivot_set::iterator i;
        cerr << "Stack smashing detected! @" << addr << endl;
        cerr << "Exiting...." << endl;
        LOG("Stack smashing detected\n");

        
        ADDRINT esp = PIN_GetContextReg(ctx, REG_STACK_PTR);
        PIN_SetContextReg(ctx, REG_STACK_PTR, esp+4);
     
        PIVOT_testpivot(ps, ctx, *tracker);
     
        FlushBuffer(true, ctx, tid, false);
        Cleanup();
        
    }
        //9/13 liu
        
    if (g_exit_next) {
        FlushBuffer(true, ctx, tid, false);
        Cleanup();
        
    }
   
    //ReleaseLock(&lock);  
    LLOG("released big thing\n");

    va_end(va);

    return;

}

VOID InstrBlock(BBL bbl)
{

    // Now we need to get the values.
  
    uint32_t valcount;
    uint32_t icount = BBL_NumIns(bbl);
  
    // Used to temporarily store the values we obtain from the operands,
    // to faciliate further analysis for fast paths.
    TempOps_t opndvals[MAX_VALUES_COUNT];
  

    // LOG("INS: BBL start.\n");

    if (g_active) {

        if (icount > BUFFER_SIZE) {
            LOG("WARNING: Basic block too many instructions: " + 
                decstr(icount) + "\n");
            assert(false);
        }

        // Add instrumentation call to check if buffer needs to be flushed.
        BBL_InsertIfCall(bbl, IPOINT_BEFORE,
                         (AFUNPTR) CheckBuffer,
                         IARG_UINT32, icount,
                         IARG_END);

        BBL_InsertThenCall(bbl, IPOINT_BEFORE,
                           (AFUNPTR) FlushBuffer,
                           IARG_BOOL, true,
                           IARG_CONTEXT,
                           IARG_THREAD_ID,
                           IARG_BOOL, true,
                           IARG_END);

    }

    //LOG("INS: BBL ins start.\n");

    // Count of instructions that have yet to be inserted into the buffer,
    // at the point at which the current instruction will be executed.
    uint32_t insLeft = icount;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

        if (!g_active && g_usetrigger) {
            // Logging has not been activated yet, so all we need to do now
            // is check for the trigger condition.

            if (INS_Address(ins) == g_trig_addr) {
                // Found the trigger address.

                INS_InsertIfCall(ins, IPOINT_BEFORE,
                                 (AFUNPTR) CheckTrigger,
                                 IARG_END);

                INS_InsertThenCall(ins, IPOINT_BEFORE,
                                   (AFUNPTR) Activate,
                                   IARG_CONTEXT,
                                   IARG_END);

            }

            // Skip the rest of the analysis and immediately go on to the
            // next instruction.
            continue;

        }

        // Skip instrumentation unless g_active is enabled
        if (!g_active) {
            continue;
        }

        // Add instrumentation call to insert instruction into buffer.

        if (INS_Category(ins) == XED_CATEGORY_X87_ALU) {

            // TODO: Handle floating point instructions.
            // LOG("Not logging FP instruction.\n");

            // cerr << "Not logging FP instruction @" << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            // continue;

        } else if (INS_Category(ins) == XED_CATEGORY_PREFETCH) {
            LOG("Not logging prefetch instruction.\n");
            cerr << "Not logging prefetch instruction @" << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            continue;
        } else if (INS_Category(ins) == XED_CATEGORY_MMX) {
            LOG("Not logging mmx instruction.\n");
            cerr << "Not logging mmx instruction @" << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            continue;
        } else if (INS_Category(ins) == XED_CATEGORY_FCMOV) {
            LOG("Not logging float move instruction.\n");
            cerr << "Not logging float move instruction @" << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            continue;
        }

        // Check if there's a REP prefix.
        if (INS_HasRealRep(ins)) {

            INS_InsertIfCall(ins, IPOINT_BEFORE,
                             (AFUNPTR) CheckBufferEx,
                             IARG_FIRST_REP_ITERATION,
                             IARG_REG_VALUE, INS_RepCountRegister(ins),
                             IARG_UINT32, insLeft,
                             IARG_END);

            INS_InsertThenCall(ins, IPOINT_BEFORE,
                               (AFUNPTR) FlushBuffer,
                               IARG_BOOL, false,
                               IARG_ADDRINT, 0,
                               IARG_THREAD_ID,
                               IARG_BOOL, true,
                               IARG_END);

        }

        // The argument list to be passed into the instruction analysis call.
        IARGLIST arglist = IARGLIST_Alloc();
        IARGLIST arglist_helper = IARGLIST_Alloc();
        valcount = 0;
      
        // The first few arguments to AppendBuffer.
        IARGLIST_AddArguments(arglist,
                              IARG_ADDRINT, INS_Address(ins),
                              IARG_THREAD_ID,
                              IARG_CONTEXT,
                              IARG_BOOL, INS_IsBranch(ins),
                              IARG_UINT32, INS_Size(ins),
                              IARG_END);

        // Now we need to gather the instruction bytes.

        // Wastes a copy, but required because the instruction may not be
        // 32-bit aligned, and we want to respect word alignment requirements.
        uint32_t rawbytes_i[4];
        // Is it an xor?
        bool is_xor = false;

        UINT sz = INS_Size(ins);
        assert(PIN_SafeCopy((void*)rawbytes_i, (const void*) INS_Address(ins), sz) == sz);
      
        IARGLIST_AddArguments(arglist,
                              IARG_UINT32, rawbytes_i[0],
                              IARG_UINT32, rawbytes_i[1],
                              IARG_UINT32, rawbytes_i[2],
                              IARG_UINT32, rawbytes_i[3],
                              IARG_END);

        for (uint32_t i = 0; i < MAX_VALUES_COUNT; i++) {
            opndvals[i].taint = 0;
            opndvals[i].type = INVALIDREGMEM;
        }

        // specializing xors
        if (INS_Mnemonic(ins) == string("XOR") ||
            INS_Mnemonic(ins) == string("PXOR")) {
            int opnum = -1;
            bool found = false;
            REG r = REG_INVALID();

            /* Find the source and destination operand. */
            for (uint32_t i = 0 ; i < INS_OperandCount(ins); i++) {
                if (INS_OperandReadAndWritten (ins, i) &&
                    INS_OperandIsReg(ins, i)) {
                } else {
                    found = true;
                    r = INS_OperandReg(ins, i);
                    opnum = -1;
                    break;
                }
            }

            /* Find the second operand, and ensure it's the same register
               as the first operand we found. */
            if (found) {
                for (uint32_t i = 0 ; i < INS_OperandCount(ins); i++) {
                    if (INS_OperandReadAndWritten (ins, i) &&
                        INS_OperandIsReg(ins, i) &&
                        r == INS_OperandReg(ins, i) &&
                        (unsigned)opnum != i) {
                        is_xor = true;
                        break;
                    }
                }
            }
        } /* end xor code */

        for(uint32_t i = 0; i < INS_OperandCount(ins); i++) {

            opndvals[valcount].taint = 0;
            if (INS_OperandRead(ins, i) && (!is_xor))
                opndvals[valcount].taint = RD;
            if (INS_OperandWritten(ins, i))
                opndvals[valcount].taint |= WR;
	
            /* Handle register operands */
            if (INS_OperandIsReg(ins, i)) {
         
                REG r = INS_OperandReg(ins, i);
                if(r == REG_INVALID()) {
                  cerr << "Warning: invalid register operand in " << INS_Disassemble(ins) << endl;
                  continue;
                }
                assert(r != REG_INVALID());
                opndvals[valcount].reg = r;
                opndvals[valcount].type.type = REGISTER;

                // This was causing problems with movd %eax, %xmm0,
                // because %xmm0's operand width is 32, but BAP needs
                // to know the full operand size, which is 128.
                // opndvals[valcount].type.size = INS_OperandWidth(ins, i);

                opndvals[valcount].type.size = GetBitsOfReg(r);

                REG fullr = REG_FullRegName(r);
                if (fullr != REG_INVALID() && fullr != r) {
                  /* We know the fuller register, so just use that! */
                    //	      cerr << "partial " << REG_StringShort(r) << " full " << REG_StringShort(fullr) << endl;
                    opndvals[valcount].reg = fullr;
                    opndvals[valcount].type.type = REGISTER;
                    opndvals[valcount].type.size = GetBitsOfReg(fullr);
                }

                valcount++;

            } else if (INS_OperandIsMemory(ins, i) ||
                       INS_OperandIsAddressGenerator(ins, i)) {


                /* Note: Compiled code sometimes uses LEA instructions for
                 * arithmetic.  As such, we always want to treat reads of
                 * these base/index registers as tainted. */

                REG basereg = INS_OperandMemoryBaseReg(ins, i);
                if (basereg != REG_INVALID()) {

                    opndvals[valcount].reg = basereg;
                    opndvals[valcount].type.type = REGISTER;
                    opndvals[valcount].type.size = GetBitsOfReg(basereg);

                    if (TaintedIndices || INS_OperandIsAddressGenerator(ins, i))
                        opndvals[valcount].taint = RD;
                    else
                        opndvals[valcount].taint = 0;

                    valcount++;

                }

                REG idxreg = INS_OperandMemoryIndexReg(ins, i);
                if (idxreg != REG_INVALID()) {

                    opndvals[valcount].reg = idxreg;
                    opndvals[valcount].type.type = REGISTER;
                    opndvals[valcount].type.size = GetBitsOfReg(idxreg);

                    if (TaintedIndices || INS_OperandIsAddressGenerator(ins, i))
                        opndvals[valcount].taint = RD;
                    else
                        opndvals[valcount].taint = 0;

                    valcount++;              

                }
            } 	   
        }

        bool memRead = INS_IsMemoryRead(ins);
        bool memRead2 = INS_HasMemoryRead2(ins);
        bool memWrite = INS_IsMemoryWrite(ins);

        // Value type of memory read.
        RegMem_t memReadTy = {NONE , 0};
        if (memRead || memRead2) {
            memReadTy.size = (INS_MemoryReadSize(ins) * 8); 
            memReadTy.type = MEM;
        }
        // Value type of memory write
        RegMem_t memWriteTy = {NONE , 0};
        if (memWrite) {
            memWriteTy.size = (INS_MemoryWriteSize(ins) * 8); 
            memWriteTy.type = MEM;
        }
         
        // Insert the operand values we've previously identified into the arglist.
        for (unsigned int i = 0; i < valcount; i++) {

            // cerr << opndvals[i].type << " " << i << " " << valcount << endl;
        
            // LOG("Adding: " + REG_StringShort((REG)opndvals[i].reg) + "\n");

            /*
             * PIN has several ways of passing register values to analysis
             * functions.  Unfortunately, none of them works all the
             * time.  So, we need to decide how to pass the value, and set
             * the *_value arguments to AppendBuffer accordingly.
             */
            switch (howPass((REG) opndvals[i].reg)) {
            case P_FPX87:
            case P_CONTEXT:
                IARGLIST_AddArguments(arglist_helper,
                                      IARG_UINT32, (uint32_t)(opndvals[i].type.type),
                                      IARG_UINT32, opndvals[i].type.size,
                                      IARG_UINT32, opndvals[i].reg,
                                      /* We don't need the value
                                         argument for contexts */
                                      IARG_PTR, 0,
                                      IARG_UINT32, opndvals[i].taint,
                                      IARG_END);        
                break;

            case P_REF:
                IARGLIST_AddArguments(arglist_helper, 
                                      IARG_UINT32, (uint32_t)(opndvals[i].type.type),
                                      IARG_UINT32, opndvals[i].type.size,
                                      IARG_UINT32, opndvals[i].reg,
                                      /* Pass reference pointer */
                                      IARG_REG_CONST_REFERENCE, opndvals[i].reg,
                                      IARG_UINT32, opndvals[i].taint,
                                      IARG_END);        
                break;
              
            default:
                cerr << "Unknown value passing method" << endl;
                assert(false);
            }
        }

        /* We break up memory operands into byte-wise operands.  This is
         * essential for taint analysis.  Code that utilizes taint
         * analysis assumes that a tainted value can be computed (e.g.,
         * symbolically executed) using the instructions in the trace.
         * However, if some of a memory operand are not tainted, then
         * they could have changed.  Thus, we must break up memory
         * operands to make this explicit. */
      
        if (memRead) {
            uint32_t bytes = GetByteSize(memReadTy);
        
            for (uint32_t offset = 0; offset < bytes; offset++) {
                IARGLIST_AddArguments(arglist_helper,
                                      IARG_UINT32, (uint32_t)MEM,
                                      IARG_UINT32, 8, // one byte
                                      IARG_MEMORYREAD_EA,
                                      //IARG_MEMORYREAD_SIZE,
                                      IARG_UINT32, offset,
                                      IARG_UINT32, RD,
                                      IARG_END);
                valcount++;
            }
        }

        if (memRead2) {
            uint32_t bytes = GetByteSize(memReadTy);

            for (uint32_t offset = 0; offset < bytes; offset++) {        
                IARGLIST_AddArguments(arglist_helper,
                                      IARG_UINT32, (uint32_t)MEM,
                                      IARG_UINT32, 8, // one byte
                                      IARG_MEMORYREAD2_EA,
                                      //IARG_MEMORYREAD_SIZE,
                                      IARG_UINT32, offset,
                                      IARG_UINT32, RD,
                                      IARG_END);
                valcount++;
            }
        }

        if (memWrite) {
            uint32_t bytes = GetByteSize(memWriteTy);

            for (uint32_t offset = 0; offset < bytes; offset++) {        
          
                IARGLIST_AddArguments(arglist_helper,
                                      IARG_UINT32, (uint32_t)MEM,
                                      IARG_UINT32, 8, // one byte
                                      IARG_MEMORYWRITE_EA,
                                      //IARG_MEMORYWRITE_SIZE,
                                      IARG_UINT32, offset,
                                      IARG_UINT32, WR,
                                      IARG_END);
                valcount++;
            }
        }

        if (INS_SegmentPrefix(ins)) {
            REG seg = INS_SegmentRegPrefix(ins);
            /* Pin only has base registers for FS and GS (probably since
               Linux uses GS, and Windows uses FS. So, we'll just output a
               base register if we see one of those for now, and hope we
               don't need ES/etc. */
            if (seg == REG_SEG_FS || seg == REG_SEG_GS) {
                REG addreg;

                /* Set the register to add to the buffer */
                switch(seg) {
                case REG_SEG_FS:
                    addreg = REG_SEG_FS_BASE;
                    break;
	    
                case REG_SEG_GS:
                    addreg = REG_SEG_GS_BASE;
                    break;

                default:
                    assert(false);
                    break;
                }

                IARGLIST_AddArguments(arglist_helper,
                                      IARG_UINT32, (uint32_t)REGISTER,
                                      IARG_UINT32, 32, // Register size in bits
                                      IARG_UINT32, addreg,
                                      //IARG_MEMORYWRITE_SIZE,
                                      IARG_PTR, 0,
                                      IARG_UINT32, 0,
                                      IARG_END);	  
                valcount++;
            }
        }



        // TODO: Check if valcount has exceed the maximum number of
        // values. Also, figure out what to do if so.

        if (valcount >= MAX_VALUES_COUNT) {
            cerr << "Error: Too many values (" << valcount << "). Max: " << MAX_VALUES_COUNT << endl;
            cerr << "Instruction: " << INS_Disassemble(ins) << endl;
            cerr << "Category: " << CATEGORY_StringShort(INS_Category(ins)) << endl;
        }
        assert(valcount < MAX_VALUES_COUNT);
      

        IARGLIST_AddArguments(arglist,
                              IARG_UINT32, valcount,
                              IARG_END);

        /* Now, add the operands. */
        IARGLIST_AddArguments(arglist,
                              IARG_IARGLIST, arglist_helper,
                              IARG_END);

        // The argument list has been built, time to insert the call.

        INS_InsertCall(ins, IPOINT_BEFORE,
                       (AFUNPTR) AppendBuffer,
                       IARG_IARGLIST, arglist,
                       IARG_END);

        // If we are logging one instruction after exiting the recording
        // range, then arrange for the post instruction call to happen
        // if ins is outside of the range.
        if (LogOneAfter.Value() && !(INS_Address(ins) >= start_addr && INS_Address(ins) <= end_addr)) {
            cerr << "found the last one" << endl;
            if (INS_IsBranchOrCall(ins)) {
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                               (AFUNPTR) PostInstruction,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_CONTEXT,
                               IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_AFTER,
                               (AFUNPTR) PostInstruction,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_CONTEXT,
                               IARG_END);
            }
        }
      
        insLeft--;

        // Free the memory.
        IARGLIST_Free(arglist);
        IARGLIST_Free(arglist_helper);

    }

    //LOG("INS: bbl ins end.\nINS: BBL end.\n");
   

}

//1208////////////////////////////////////////////////
static bool DoWriteAddr(ADDRINT addr) 
{
    IMG i = IMG_FindByAddress(addr);
    if (IMG_Valid(i))
	{
        char tempbuf[BUFSIZE];
        char *tok = NULL;
        char *lasttok = NULL;
        // Fill up the temporary buffer
        strncpy(tempbuf, IMG_Name(i).c_str(), BUFSIZE);    
        // We don't need a lock, since this is an instrumentation function (strtok is not re-entrant)
        strtok(tempbuf, "/");
        while ((tok = strtok(NULL, "/")) != NULL)
		{
            // Just keep parsing...
            lasttok = tok;
        }
        if (lasttok)
		{
			//liu
            if (strcmp(lasttok,CoverageModule)==0)
			{
                return true;
            }
        }
    }
    return false;
}



VOID ThreadEnd(THREADID threadid, CONTEXT *ctx, INT32 code, VOID *v)
{
    ThreadInfo_t *ti = NULL;
  
    //cerr << "Thread " << threadid << " ending" << endl;

    // Free thread-local data
    //liu 911
    thread_info1[threadid].taint_prop = false;
    thread_info1[threadid].trace_file.close();
    ti = GetThreadInfo();
  
    delete ti;
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctx, INT32 flags, VOID *v)
{
    // Get the command line arguments before _start is called
    // This only works with Linux conventions in mind
    //static int firstthread = true;

    LLOG("new thread\n");
  
    NewThreadInfo();

    //GetLock(&lock, threadid+1);
  
    LOG("New thread starting\n");
    //cerr << "Thread " << threadid << " starting" << endl;
    //liu 911
    if (threadid != 0)
        InitLogs(threadid);
  //by richhard，初始化寄存器污点源数组指针
    thread_info1[threadid].ptaintsrc_table=perthread_taintsrctable[threadid];

    thread_info1[threadid].taint_prop = true;
    

    //ReleaseLock(&lock);  

}
void SetRegisterTaintSrc(set<int> taintsrc, REG r, THREADID id, ADDRINT iaddr);
void SetRegisterTaint(bool is_tainted, REG r, THREADID id, ADDRINT iaddr);
//liu 1012
static void After_crc32(CONTEXT *ctxt,THREADID tid)
{
    int crc32=PIN_GetContextReg(ctxt, REG_EAX);
    cout<<"get crc32: "<<hex<<crc32<<endl;
    crc32_Instrumentation_On = true;
    TAINT_Analysis_On=true;
  
    TAINT_Instrumentation_On = true;
    SetRegisterTaint( true, REG_EAX,tid, 0);
    set<int> tmp;
    tmp.insert(1);
    tmp.insert(2);
    SetRegisterTaintSrc(tmp,REG_EAX,tid,0);
}

VOID ModLoad(IMG img, VOID *v)
{

    const string &name = IMG_Name(img);
    //crc32_Instrumentation_On = false;
    //cout<<"so: "<<name<<endl;
        // Skip all images, but kernel32.dll  libz.so.1.2.3.4
    
    
	//1015 coverage low high addrs
	if(strstr(name.c_str(),CoverageModule) != NULL)
	{
			DllbaseAddress = IMG_LowAddress(img);
            int DllbaseAddress1 = IMG_HighAddress(img);
            TraceFile<<"lowaddr: "<<hex<<DllbaseAddress<<" highaddr: "<<DllbaseAddress1<<endl;


	}
 
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
    ThreadInfo_t *ti = NULL;
    SyscallInfo_t si;
    ti = GetThreadInfo();
    
    si.sf.mutable_syscall_frame()->set_address(PIN_GetContextReg(ctx, REG_INST_PTR));

    si.sf.mutable_syscall_frame()->set_thread_id(tid);

    si.sf.mutable_syscall_frame()->set_number(PIN_GetSyscallNumber(ctx, std));

    for (int i = 0; i < MAX_SYSCALL_ARGS; i++)
    {
        if (i < PLAT_SYSCALL_ARGS) {
            si.sf.mutable_syscall_frame()->mutable_argument_list()->add_elem(PIN_GetSyscallArgument(ctx, std, i));
        }
    }

  
    if (tracker->taintPreSC(si.sf.mutable_syscall_frame()->number(), (const uint64_t *) (si.sf.syscall_frame().argument_list().elem().data()), si.state)) 
    {
        // Do we need to do anything here? ...
    }
  
    ti->scStack.push(si);
  
    
}



VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
    ThreadInfo_t *ti = NULL;
    SyscallInfo_t si;
    uint32_t addr, length;


    LLOG("sysexit\n");
 
    ti = GetThreadInfo();
 
    si = ti->scStack.top();
    ti->scStack.pop();

    //GetLock(&lock, tid+1);
  
    // Check to see if we need to introduce tainted bytes as a result of this
    // sytem call
    FrameOption_t fo = tracker->taintPostSC(PIN_GetSyscallReturn(ctx, std), (const uint64_t*) (si.sf.syscall_frame().argument_list().elem().data()), addr, length, si.state);

    if (fo.b) {
        if (!g_taint_introduced) {
            // Activate taint tracking
            TActivate();
        }
        
    }

    tracker->postSysCall(ti->delta);

}



VOID FollowParent(THREADID threadid, const CONTEXT* ctxt, VOID * arg)
{
    int i;

    //LLOG("fparent\n");
  
    GetLock(&lock, threadid+1);
    i = strlen(g_threadname);
    assert(i < BUFFER_SIZE);
    if(i!=0)
    {
        g_threadname[i++] = 'p';
    }

    std::cerr << "Spawning parent: " << PIN_GetPid() <<" "<< g_threadname << std::endl;
    //liu 11 9 
    stringstream file_addrs;
    //stringstream file_assist;
    file_addrs<<g_threadname<< KnobOut.Value() << "-" << "addrs.txt";
    //file_assist<<g_threadname<<KnobOut.Value() << "-" << "assist.txt";
    strcpy(buf_file_addrs,file_addrs.str().c_str());
    //strcpy(buf_file_assist,file_assist.str().c_str());

    ReleaseLock(&lock);  
}
 VOID FollowChild(THREADID threadid, const CONTEXT* ctxt, VOID * arg)
{
    int i;

    //LLOG("follow child\n");
  
    GetLock(&lock, threadid+1);
    //liu 11 9
    i = strlen(g_threadname);
    assert(i < BUFFER_SIZE);
    g_threadname[i++] = 'c';
    stringstream ss;
    stringstream file_addrs;
    //stringstream file_assist;
    //1108 liu
    ss <<g_threadname<< KnobOut.Value() << "-" << "trace.bpt";
    file_addrs<<g_threadname<< KnobOut.Value() << "-" << "addrs.txt";
    //file_assist<<g_threadname<<KnobOut.Value() << "-" << "assist.txt";
    strcpy(buf_file_addrs,file_addrs.str().c_str());
    //strcpy(buf_file_assist,file_assist.str().c_str());
    //printf("%s\n%s\n",file_addrs.str().c_str(),file_assist.str().c_str());
    //ss << PIN_GetPid() << "-" << KnobOut.Value();

    //g_twnew = new TraceContainerWriter(ss.str().c_str(), bfd_arch_i386, bfd_mach_i386_i386, default_frames_per_toc_entry, false);

    g_bufidx = 0;
    g_kfcount = 0;
    //1208/////////////////////////////////
    g_tsbufidx = 0;
    //////////////////
   //9 20 liu
    cleanup_flag=0;
    start_time = time(0);
    g_time = (time_t)KnobTime.Value();
    //g_time=10;
    cout << g_time<<endl;
    
    g_logcount = 0;
    g_loglimit = KnobLogLimit.Value();
    //1208////////////////////////////////////////////
    g_Execlimit = KnobInsLimit.Value();
    ////////////
    g_skipTaints = SkipTaints.Value();

    g_timer = clock();

    g_exit_next = false;
   
    start_addr = TaintStart.Value();
    end_addr = TaintEnd.Value();
    /*
    i = strlen(g_threadname);
    assert(i < BUFFER_SIZE);
    g_threadname[i++] = 'c';

    g_twnew = new TraceContainerWriter((g_threadname + KnobOut.Value()).c_str(), bfd_arch_i386, bfd_mach_i386_i386, default_frames_per_toc_entry, false);
  
    g_bufidx = 0;
    g_kfcount = 0;
  
    g_logcount = 0;
    g_loglimit = KnobLogLimit.Value();
    //1208///////////////////////////////////////
    g_Execlimit = KnobInsLimit.Value();
    g_timer = clock();
    */
    std::cerr << "Spawning child: " << PIN_GetPid() <<" "<< g_threadname << std::endl;
    ReleaseLock(&lock);
  
}

bool FollowExec(CHILD_PROCESS cp, VOID *v) {
    bool follow = false;  
    int argc;
    const char * const * argv;
  
    CHILD_PROCESS_GetCommandLine(cp, &argc, &argv);
    assert (argc >= 0);
    cerr << "Exec: ";
    for (int i = 0; i < argc; i++) {
        cerr << argv[i] << " ";
    }
    cerr << endl;
  
    /* See if we should follow this */
    for (unsigned int i = 0; i < FollowProgs.NumberOfValues(); i++) {
        if (FollowProgs.Value(i) == argv[0]) {
            follow = true;
        }
    }


    if (follow)
        cerr << "Following" << endl;
    else
        cerr << "Not following" << endl;

#ifndef _WIN32
    /* If we're on Linux, this means we're about to call execv(), and
     * we're going to disappear! We had better write out our trace! */

    cerr << "Flushing buffer before execv()" << endl;
    FlushBuffer(false, NULL, PIN_ThreadId(), true);
    Cleanup();
#endif

    return follow;
}
//10 9 liu
int mydisam(char*buf,uint32_t myaddress,FILE * fp)

{

 
  //cs_close(&handle);

  return 0;
 }
 int LogExcepAsmCode(UINT  dwExceptionAddress,FILE * fp)
{

  char   szBuffer[100];
  #define   CODE_LENGTH   30
  #define   CODE_LENGTH2  60
  if(fp==NULL)
  {
    return FALSE;
  }
  memset(szBuffer, 0, sizeof(szBuffer));
  PIN_SafeCopy(szBuffer,(void *)(dwExceptionAddress), CODE_LENGTH);
  
  mydisam(szBuffer,dwExceptionAddress,fp);
  
  return TRUE;
}
VOID ExceptionHandler(THREADID threadid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v) 
{
    

    frame f;
    int tmpflag=0;
    char buffer[512];
    f.mutable_exception_frame()->set_exception_number(info);
    f.mutable_exception_frame()->set_thread_id(threadid);
    if (from) {
        f.mutable_exception_frame()->set_from_addr(PIN_GetContextReg(from, REG_INST_PTR));
    }
    if (to) {
        f.mutable_exception_frame()->set_to_addr(PIN_GetContextReg(to, REG_INST_PTR));
    }
    cout<<"exception!!!!!!!!!!!!!!!!"<<endl;
    GetLock(&lock, threadid+1);  
    LLOG("got except lock!\n");

    // If we want the exception to be the last thing in the trace when
    
    FlushBuffer(false, from, threadid, false);
    //g_twnew->add(f);
    cout<<"reason 2= "<<reason<<endl;
    if (reason == CONTEXT_CHANGE_REASON_FATALSIGNAL||CONTEXT_CHANGE_REASON_SIGNAL==reason) {
        cout<<"reason 1= "<<reason<<endl;
        std::cerr << "Received fatal signal " << info << endl;
        ADDRINT pc = PIN_GetContextReg(from, REG_INST_PTR);
        IMG i = IMG_FindByAddress(pc);
        //cerr << "********Received  exception @0x" << pc << " " << info << " in thread " << threadid <<           "********"<<endl;
        stringstream ss;
        ss << KnobOut.Value()<< "-" <<"exception.txt";
        FILE *fp = fopen(ss.str().c_str(), "wb");
        if(IMG_Valid(i))
          sprintf(buffer,"Exception signal=0x%x address=0x%x moudle=%s tid=%d\r\n",info,pc,IMG_Name(i).c_str(),threadid);
        else
          sprintf(buffer,"Exception signal=0x%x address=0x%x moudle=%s tid=%d\r\n",info,pc,"nomodule",threadid);
        fwrite(buffer,1,strlen(buffer),fp);
        sprintf(buffer,"Registers:  EAX=0x%x  EBX=0x%x  ECX=0x%x  EDX=0x%x; "
                "ESI=0x%x  EDI=0x%x  EBP=0x%x  ESP=0x%x; EIP=0x%x  CS=0x%x  "
                "DS=0x%x  FS=0x%x;\n",PIN_GetContextReg(from, REG_EAX),
                PIN_GetContextReg(from, REG_EBX),PIN_GetContextReg(from, REG_ECX),
                PIN_GetContextReg(from, REG_EDX),PIN_GetContextReg(from, REG_ESI),
                PIN_GetContextReg(from, REG_EDI),PIN_GetContextReg(from, REG_EBP),
                PIN_GetContextReg(from, REG_ESP),PIN_GetContextReg(from, REG_EIP),
                PIN_GetContextReg(from, REG_SEG_CS),PIN_GetContextReg(from, REG_SEG_DS),
                PIN_GetContextReg(from, REG_SEG_FS));
        fwrite(buffer,1,strlen(buffer),fp);
        LogExcepAsmCode(pc,fp);
    
        // log callstack
        uint32_t eip = PIN_GetContextReg(from, REG_EIP);
        //uint32_t esp = PIN_GetContextReg(from, REG_ESP);
        uint32_t ebp = PIN_GetContextReg(from, REG_EBP);
        uint32_t childebp = 0;
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer,"Callstack:\nFramePtr ChildRBP RetAddr\n");
        fwrite(buffer,1,strlen(buffer),fp);
        int count = 0;
        memset(buffer, 0, sizeof(buffer));
        while(ebp != 0 && count < 20)
          {
              if(PIN_SafeCopy(&childebp, (uint32_t *)(ebp), 4) == 4) 
                printf("childebp:%x,ebp:%x\n",childebp,ebp);
              if(PIN_SafeCopy(&eip, (uint32_t *)(ebp + 4), 4) == 4) 
                    printf("eip:%x\n",eip);             
              sprintf(buffer,  "0x%x 0x%x    0x%x\r\n", 
                  ebp, childebp, eip);
              fwrite(buffer,1,strlen(buffer),fp);
              //if(PIN_SafeCopy(&ebp, (uint32_t *)ebp, 4) != 4) 
                 //printf("ebp:\n",ebp);
              ebp = childebp;
              count++;
          }
        fclose(fp);
        FlushBuffer(false, from, threadid, false);
        tmpflag=1;
        
        
    } 

    ReleaseLock(&lock);
    if(tmpflag==1)
    {
        Cleanup();
    }
}


VOID Fini(INT32 code, VOID *v)
{
    //LOG("In Fini");
    cout<<"In fini"<<endl;
    TraceFile<<"final taint map"<<endl;
    dump_taint_src();
    Cleanup();
}

// Caller responsible for mutual exclusion
void cleandir()
{
    remove("/home/bap/workspace/bap-0.7/pintraces/1-1-addrs.txt");
    remove("/home/bap/workspace/bap-0.7/pintraces/1-1-0logs.txt");
}

VOID Cleanup()
{
    ofstream fpaddrs;
    GetLock(&lock, 1);

    if(cleanup_flag==0)
    {
        cleanup_flag=1;
        //g_twnew->finish();
        //liu 11 9
        //printf("%s\n%s\n",buf_file_addrs,buf_file_assist);

        fpaddrs.open(buf_file_addrs,ios::app);

        list<branch_st>::iterator iter;

        //1208/////////////////////////////////////////////////\C9\FA\B3\C9assist.txt
        for(iter=g_bbls.begin();iter!=g_bbls.end();++iter)
        { 
            fpaddrs<<hex<<iter->addr<<" "<<iter->taken<<endl;
        }
        
        fpaddrs.close();
        //liu 11 9
    	//stringstream ss;
    	//ss << KnobOut.Value()<<"-"<<"assist.txt";
    	//FILE *fp = fopen(buf_file_assist, "wb");
    	//fwrite(g_TaintAsistBuff, 4, g_tsbufidx + 1, fp);
    	//fclose(fp);
        cerr << "cleanup"<<endl;
        std::cerr << " process: " << PIN_GetPid() <<" "<< g_threadname << std::endl;
        
    }
    ReleaseLock(&lock);
     
    exit(0);
    

}

INT32 Usage()
{
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/*
int mylog(char * log)
{
    int to_fd;
    if ((to_fd = open("log.txt", O_WRONLY | O_CREAT | O_APPEND , S_IRUSR | S_IWUSR)) == -1) {  
        fprintf(stderr, "Open  Error\n");  
        exit(1);  
    }
    write(to_fd, log, strlen(log));
    close(to_fd); 
    return 1;
}*/


int main(int argc, char *argv[])
{
    stringstream ss;
    cerr << hex;
    cleandir();
    PIN_InitSymbols();

    if (PIN_Init(argc,argv))
        return Usage();

    InitLock(&lock);
    InitLock(&lock1);
    //liu 911
    InitLogs(0);
    InitInstr();//初始化instruction函数处理数组
    //liu 911
    // Check if a trigger was specified.
    if (KnobTrigAddr.Value() != 0) {
        g_usetrigger = true;
        g_trig_resolved = false;

        // Set trigger countdown to initial value.
        g_trig_countdown = KnobTrigCount.Value();
      
    } else {
        g_usetrigger = false;
    }
	//1208//liu
	sprintf(CoverageModule,"%s",KnobCoverage.Value().c_str());
    // Check if taint tracking is on
    if (KnobTaintTracking.Value()) {
        tracker = new TaintTracker(values);
        for (uint32_t i = 0 ; i < TaintedFiles.NumberOfValues() ; i++) {
            if (TaintedFiles.Value(i) != "") {
                tracker->trackFile(TaintedFiles.Value(i));
            }
        }

        tracker->setTaintArgs(TaintedArgs);
        if (TaintedStdin)
            tracker->setTaintStdin();
        if (TaintedNetwork)
            tracker->setTaintNetwork();
        if (TaintedEnv.Value() != "")
            tracker->setTaintEnv(TaintedEnv.Value());
    }
	//1208//liu
	
	uint32_t NumOffsetsParams;
	NumOffsetsParams =  TaintedOffsets.NumberOfValues()>>1;
	      
	for (uint32_t j = 0; j <NumOffsetsParams; j++) 
	{
	//if (TaintedOffsets.Value(2*j) != 0 && TaintedOffsets.Value(2*j+1) != 0)
	//{
	    tracker->trackOffset(TaintedOffsets.Value(2*j),TaintedOffsets.Value(2*j+1));
	
	}
	///////////////

    /* Get a key for thread info */
    tl_key = PIN_CreateThreadDataKey(NULL);
    assert(tl_key != -1);

    // We must activate taint tracking early if we have tainted args
    // or envs
    if ((TaintedEnv.Value() != "") || TaintedArgs.Value()) {
        g_taint_introduced = true;
    } else {
        g_taint_introduced = false;
    }
	//1208
    //liu 11 9
    /*
	stringstream ss2;
    ss2 <<KnobOut.Value()<<"-"<<"addrs.txt";
	fpaddrs.open(ss2.str().c_str());
    fpaddrs<<"meili"<<endl;
    */
    //liu 11 9
    stringstream file_addrs;
    //stringstream file_assist;
    file_addrs<< KnobOut.Value() << "-" << "addrs.txt";
    //file_assist<<KnobOut.Value() << "-" << "assist.txt";
    strcpy(buf_file_addrs,file_addrs.str().c_str());
    //strcpy(buf_file_assist,file_assist.str().c_str());


	
    
    IMG_AddInstrumentFunction(ModLoad, 0);
    //TRACE_AddInstrumentFunction(InstrTrace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction((THREAD_FINI_CALLBACK)ThreadEnd, 0);
   
    //PIN_AddContextChangeFunction(ExceptionHandler, 0);
   
    /*
    FPOINT_AFTER_IN_PARENT   Call-back in parent, immediately after fork.  
    FPOINT_AFTER_IN_CHILD    Call-back in child, immediately after fork.
    */
    //PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, FollowChild, 0);
    //PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, FollowParent, 0);

    //PIN_AddFollowChildProcessFunction(FollowExec, 0);
   
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
    //liu 911
    //INS_AddInstrumentFunction(InstructionProp, 0); //污点传播
    //liu 1010 
    INS_AddInstrumentFunction(InstructionProp, 0); //污点传播
   
    PIN_AddFiniFunction(Fini, 0);
    //1208/////////////////////////////////////////////////
    //liu 11 9
	ss << g_threadname<<KnobOut.Value() << "-" << "trace.bpt";
    //ss << PIN_GetPid() << "-" << KnobOut.Value();
    //liu 925
   iTNTChksmDegree = KnobChksmDegree.Value();
    //g_twnew = new TraceContainerWriter(ss.str().c_str(), bfd_arch_i386, bfd_mach_i386_i386, default_frames_per_toc_entry, false);

    g_bufidx = 0;
    g_kfcount = 0;
	//1208/////////////////////////////////
	g_tsbufidx = 0;
	//////////////////
   //9 20 liu
    cleanup_flag=0;
    start_time = time(0);
    g_time = (time_t)KnobTime.Value();
    //g_time=10;
    cout << g_time<<endl;
    
    g_logcount = 0;
    g_loglimit = KnobLogLimit.Value();
    //1208////////////////////////////////////////////
    g_Execlimit = KnobInsLimit.Value();
	////////////
    g_skipTaints = SkipTaints.Value();

    g_timer = clock();

    g_exit_next = false;
   
    start_addr = TaintStart.Value();
    end_addr = TaintEnd.Value();

    //cerr << "Code cache limit is " << CODECACHE_CacheSizeLimit() << endl;
    assert(CODECACHE_ChangeCacheLimit(CacheLimit.Value()));

    LOG("Starting program\n");
    cerr << "Starting program" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;

}
