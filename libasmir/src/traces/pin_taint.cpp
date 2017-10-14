#include "pin.H"
#include "pin_taint.h"
#include "pin_frame.h"
#include "pin_syscalls.h"
#include "winsyscalls.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include "trace.container.hpp"
#include <stdio.h>
#include <string.h>
#include <algorithm> 
#include <list>
using namespace std;
#ifndef _WIN32
#include <unistd.h>
#endif
#include <cassert>
#include <sstream>

#ifdef _WIN32
/**
 * Getting WDK header files to include is a nightmare.  If you need to
 * change this, talk to me.
 *
 * -ejs
 */
namespace WINDOWS {
  // Define a target architecture for WDK
#define _X86_ 
#include "Wdm.h"
#undef _X86_
}

// Needed for STATUS_SUCCESS to work
typedef WINDOWS::NTSTATUS NTSTATUS;
#else
const unsigned int UNIX_SUCCESS = 0;
const unsigned int UNIX_FAILURE = -1;
#endif

using namespace std;
using namespace pintrace;
//1208////////////////////////////////
extern uint32_t  g_TaintAsistBuff[5120];
extern uint32_t  g_tsbufidx;

/** Skip this many taint introductions. */
int g_skipTaints = 0;

/** Reuse taint ids? */
const bool reuse_taintids = true;
char openfilename[1000];
//9 19 liu
int state=0;
//liu global 911

bool CompactLog = true;
#define REMOVE_REP 0
#define NR_REG(_TYPE) ((_TYPE ## _LAST) - (_TYPE ## _BASE) + 1)
bool TAINT_Instrumentation_On = false;
InstrumentFunction instrument_functions[XED_ICLASS_LAST];
unsigned int setmem_untaint = 0;
unsigned int setmem_taint = 0;
#define KnobDebug 0
#define DEBUG_MOV 0
bool Measurement = false;
bool TraceSrcLog=false;
#define TraceFile ((thread_info1[(PIN_ThreadId()<0)? 0 :PIN_ThreadId()].trace_file))
per_thread thread_info1[MAX_NUM_CPUS];
//内存污点源映射表
list <TaintSourceEntry> memTaintSrcTable;
// TraceFile points to the thread-local trace file
PIN_LOCK lock;
PIN_LOCK lock1;
bool TAINT_Analysis_On = false;
char mem_taint[TAINT_TABLE_SIZE+1];
#define RECORD_REP_COUNT 1
#define REMOVE_MEM_ADDRESSING 0
#define IFCOND(x) (INS_InsertIfCall(x, IPOINT_BEFORE, (AFUNPTR)PropTaint, \
                   IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_END))
TNT_mem TNT_mem_node;
set<int> perthread_taintsrctable[MAX_NUM_CPUS][REG_XMM_LAST+1];

unsigned int iTNTEncryDegree=10;  //taint count
unsigned int iTNTChksmDegree=10;  //taint count
//liu 925
typedef struct TempOps_s {
    uint32_t reg;
    RegMem_t type;
    uint32_t taint;
} TempOps_t;
/**************** Helper **********************/
//PIN_LOCK lock1;
//PIN_LOCK lock2;
/*
int mylog(char * log)
{
    int to_fd;
    GetLock(&lock1, 1111);
    if ((to_fd = open("log.txt", O_WRONLY | O_CREAT | O_APPEND , S_IRUSR | S_IWUSR)) == -1) {  
        fprintf(stderr, "Open  Error\n");  
        exit(1);  
    }
    write(to_fd, log, strlen(log));
    close(to_fd); 
    ReleaseLock(&lock1);
    return 1;
}*/
/*
PIN_LOCK lock3;
int read_file(char * log,char * filename)
{
    int to_fd;
    GetLock(&lock3, 1111);
    if ((to_fd = open(filename, O_RDONLY , S_IRUSR | S_IWUSR)) == -1) {  
        cerr<<"Open  Error\n"; 
        ReleaseLock(&lock3);
        return 0;  
    }
    read(to_fd, log, 20);
    close(to_fd); 
    ReleaseLock(&lock3);
    return 1;
}
PIN_LOCK lock4;
int write_file(char * log,char * filename)
{
    int to_fd;
    GetLock(&lock4, 1111);
    if ((to_fd = open(filename, O_WRONLY | O_CREAT  , S_IRUSR | S_IWUSR)) == -1) {  
        fprintf(stderr, "Open  Error\n");  
        exit(1);  
    }
    write(to_fd, log, strlen(log));
    close(to_fd); 
    ReleaseLock(&lock4);
    return 1;
}*/
/** Convert a wide string to a narrow one
 */
//liu func 911
string   itoHex(size_t i)
{
    std::stringstream   s;
    s << hex<<i;
    return s.str();
} 
string PrintSet(set<int>& OffsetSet)
{
  string result;
  set<int>::iterator it;
  for(it=OffsetSet.begin();it!=OffsetSet.end();it++)
  {
    result+=itoHex((*it))+";";
  }
  return result;
}
inline void PrintErr(string err,string modulename,ADDRINT addr)
{
    TraceFile<<"***************************ERROR**********************************"<<endl;
    TraceFile<<"Info :"<<err<<"Module Name:"<<modulename<<"Instruction addr:"<<hex<<addr<<endl;
}
//by richard ，求两个集合的并
//输入输出：set<int>
set<int> Union(set<int> a ,set<int> b)
{

  set<int> result;
  //首先判断是否有空集合
  if(a.empty()||b.empty())
    return(result=(a.empty())?b:a);
  //两个都不为空
  set_union(a.begin(), a.end(), b.begin(), b.end(), inserter(result, result.begin()));
  return result;

}
VOID dump_taint_src()
{
    TraceFile<<"[TNT] Dump TAINT SRC: "<<endl;
    TraceFile<<"[TNT] Dump SRC Begin: "<<endl;
    list<TaintSourceEntry>::iterator it;
    TraceFile<<setw(20)<<"MemAddr"<<setw(20)<<"TaintSrc"<<endl;
    
    for(it=memTaintSrcTable.begin();it!=memTaintSrcTable.end();it++)
    {
        TraceFile<<setw(20)<<hex<<(*it).memaddr<<setw(20)<<PrintSet((*it).srcOffsets)<<endl;
    }
    TraceFile<<"[TNT] Dump SRC End: "<<endl;
}
ADDRINT GetRtnAddr(ADDRINT addr)
{
  RTN rtn;
  PIN_LockClient();

  rtn = RTN_FindByAddress(addr);
  ADDRINT start = RTN_Address(rtn);

  if (rtn != RTN_Invalid() && start + RTN_Size(rtn) >= addr)
  {
    PIN_UnlockClient();
    return start;
  } 
  else
  {
    PIN_UnlockClient();
    return 0;
  }
}
//liu 925
static bool REG_is_dift_eflag(REG r)
{
  if(r==REG_EFLAGS)
  {
    return true;
  }
  //多媒体扩展寄存器
  if (REG_is_mm(r) || REG_is_xmm(r))
    return true;

  //通用寄存器
  if (REG_is_gr(r))
  {
    //不处理EIP,EFLAGS和ESP
    if (r == REG_EIP || r==REG_EFLAGS||r == REG_ESP)
      return false;
    return true;
  }
  //处理到这一定是gr8和gr16（8位的和）
  if (!REG_is_gr16(r) && !REG_is_gr8(r))
    return false;

  //不处理16位的IP,FLAG,SP
  if (r == REG_IP|| r==REG_FLAGS||r == REG_SP) 
    return false;

  return true;
}
static bool REG_is_dift(REG r)
{
  //多媒体扩展寄存器
  if (REG_is_mm(r) || REG_is_xmm(r))
    return true;

  //通用寄存器
  if (REG_is_gr(r))
  {
    //不处理EIP,EFLAGS和ESP
    if (r == REG_EIP || r==REG_EFLAGS||r == REG_ESP)
      return false;
    return true;
  }
  //处理到这一定是gr8和gr16（8位的和）
  if (!REG_is_gr16(r) && !REG_is_gr8(r))
    return false;

  //不处理16位的IP,FLAG,SP
  if (r == REG_IP|| r==REG_FLAGS||r == REG_SP) 
    return false;

  return true;
}
inline bool
__GetRegisterTaint(REG r,  THREADID id) {
  return (thread_info1[id].reg_taint[r] != false);
}
ADDRINT PIN_FAST_ANALYSIS_CALL PropTaint(THREADID tid)
{
  return true;
}
static bool GetRegisterTaint(REG r, THREADID id, ADDRINT iaddr)
{


  bool is_tainted = false;

  if (!REG_is_dift(r)&&r!=REG_EFLAGS) return false;

  //先处理多媒体扩展寄存器和8位的通用寄存器
  if (REG_is_xmm(r) || REG_is_mm(r) || REG_is_gr8(r)||r==REG_EFLAGS)
  {
    if ( KnobDebug && PropTaint(id) && __GetRegisterTaint(r, id))
      TraceFile << "[TNT] " << __func__ << " PC " << hex << iaddr <<
      " reg " << REG_StringShort(r) << " is tainted " << endl;
    return __GetRegisterTaint(r, id);
  }

  assert (REG_is_gr(r) || REG_is_gr16(r));

  //处理16位和32位的通用寄存器，例如：如果ax，ah，al中一个被污染，一定有eax被污染
  switch(r)
  {
  case REG_EAX:
    is_tainted |= __GetRegisterTaint(REG_EAX, id);
  case REG_AX:
    is_tainted |= __GetRegisterTaint(REG_AH, id);
    is_tainted |= __GetRegisterTaint(REG_AL, id);
    break;
  case REG_EBX:
    is_tainted |= __GetRegisterTaint(REG_EBX, id);
  case REG_BX:
    is_tainted |= __GetRegisterTaint(REG_BH, id);
    is_tainted |= __GetRegisterTaint(REG_BL, id);
    break;
  case REG_ECX:
    is_tainted |= __GetRegisterTaint(REG_ECX, id);
  case REG_CX:
    is_tainted |= __GetRegisterTaint(REG_CH, id);
    is_tainted |= __GetRegisterTaint(REG_CL, id);
    break;
  case REG_EDX:
    is_tainted |= __GetRegisterTaint(REG_EDX, id);
  case REG_DX:
    is_tainted |= __GetRegisterTaint(REG_DH, id);
    is_tainted |= __GetRegisterTaint(REG_DL, id);
    break;
  case REG_ESI:
    is_tainted |= __GetRegisterTaint(REG_ESI, id);
  case REG_SI:
    is_tainted |= __GetRegisterTaint(REG_SI, id);
    break;
  case REG_EDI:
    is_tainted |= __GetRegisterTaint(REG_EDI, id);
  case REG_DI:
    is_tainted |= __GetRegisterTaint(REG_DI, id);
    break;
  case REG_EBP:
    is_tainted |= __GetRegisterTaint(REG_EBP, id);
  case REG_BP:
    is_tainted |= __GetRegisterTaint(REG_BP, id);
    break;
    /*case REG_ESP:
    is_tainted |= __GetRegisterTaint(REG_ESP);
    case REG_SP:
    is_tainted |= __GetRegisterTaint(REG_SP);
    break; */
  default:
    assert(0);
  }
#ifdef TACE_TAINT_INS
  if (is_tainted && PropTaint(id)) 
  {
    if (KnobDebug && PropTaint(id) && is_tainted)
      TraceFile << "[TNT] " << __func__ << " PC " << hex << iaddr <<
      " reg " << REG_StringShort(r) << " is tainted " << endl;
  }
#endif
  return is_tainted;
}
inline set<int> 
__GetRegisterTaintSrc(REG r,THREADID id) {
  return (thread_info1[id].ptaintsrc_table[r]);
}
/************************************************************************/
/* By richard 获取寄存器污染源 ,需用在GetRegisterTaint函数后,只有包含了污染数据才进行*/
/************************************************************************/
static set<int> GetRegisterTaintSrc(REG r, THREADID id, ADDRINT iaddr)
{
   set<int> taintsrc;
   //如果没有被污染，则直接返回空的污染源信息
   if(!GetRegisterTaint(r,id,iaddr))
     return taintsrc;
  //先处理多媒体扩展寄存器和8位的通用寄存器
  if (REG_is_xmm(r) || REG_is_mm(r) || REG_is_gr8(r)||r==REG_EFLAGS)
  {
    taintsrc=__GetRegisterTaintSrc(r, id);
    //assert(!taintsrc.empty());
    if(taintsrc.empty())
    {
      PrintErr("taintsrc.empty()","GetRegisterTaintSrc",iaddr);  
    }
    if (KnobDebug&&TraceSrcLog && PropTaint(id) && __GetRegisterTaint(r, id))
      TraceFile << "[TNT] " << __func__ << " PC " << hex << iaddr <<
      " reg " << REG_StringShort(r) << "taintsrc "<<PrintSet(taintsrc)<< endl;
    return taintsrc;
  }

  assert (REG_is_gr(r) || REG_is_gr16(r));

  //处理16位和32位的通用寄存器，例如：如果ax，ah，al中的一个有set有内容，则一定并在eax中
  switch(r)
  {
  case REG_EAX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_EAX, id));
  case REG_AX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_AH, id));
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_AL, id));
    break;
  case REG_EBX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_EBX, id));
  case REG_BX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_BH, id));
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_BL, id));
    break;
  case REG_ECX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_ECX, id));
  case REG_CX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_CH, id));
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_CL, id));
    break;
  case REG_EDX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_EDX, id));
  case REG_DX:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_DH, id));
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_DL, id));
    break;
  case REG_ESI:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_ESI, id));
  case REG_SI:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_SI, id));
    break;
  case REG_EDI:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_EDI, id));
  case REG_DI:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_DI, id));
    break;
  case REG_EBP:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_EBP, id));
  case REG_BP:
    taintsrc = Union(taintsrc,__GetRegisterTaintSrc(REG_BP, id));
    break;
  default:
    assert(0);
  }
  if ( KnobDebug&&TraceSrcLog && PropTaint(id) && __GetRegisterTaint(r, id))
    TraceFile << "[TNT] " << __func__ << " PC " << hex << iaddr <<
    " reg " << REG_StringShort(r) << "With TaintSrc "<<PrintSet(taintsrc)<< endl;
  //assert(!taintsrc.empty());
  if(taintsrc.empty())
  {
    PrintErr("taintsrc.empty()","GetRegisterTaintSrc",iaddr);
  }
  return taintsrc;
}
bool ConditinalJmp(INS ins)
{
  xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins); 
  if ( opcode==  XED_ICLASS_JB||
     opcode== XED_ICLASS_JBE||
     opcode== XED_ICLASS_JL ||
     opcode== XED_ICLASS_JLE||
     opcode== XED_ICLASS_JNB||
     opcode==XED_ICLASS_JNBE||
     opcode==XED_ICLASS_JNL||
     opcode==XED_ICLASS_JNLE||
     opcode==XED_ICLASS_JNO||
     opcode==XED_ICLASS_JNS||
     opcode==XED_ICLASS_JNZ||
     opcode==XED_ICLASS_JO||
     opcode==XED_ICLASS_JRCXZ||
     opcode==XED_ICLASS_JS||
     opcode==XED_ICLASS_JZ)
  {
    return true;
  }
  return false;
}
bool UnimplementedInstruction(INS ins)
{
  return false;
}



//by richard ,输出集合中的元素









//定义迭代器，用于memTaintSrcTable中地址项的查找
class FindAddrFromList
{
public:
    FindAddrFromList(const uint addr):m_addr(addr){}
    bool operator()(const list<TaintSourceEntry>::value_type &value)
    {
        return ( value.memaddr== m_addr);
    }
private:
    uint m_addr;
};

//获取某段内存区域中污点信息，如果其中有一字节内存标记为污点，那么该段区域全部标记为污点。
bool Getmem_taint(ADDRINT addr, UINT32 size, ADDRINT instr)
{


  bool is_tainted = false;

  for (UINT32 i = 0; i < size; i ++)
  {
    int accessAddr = addr+i;
    int idx = getTableIndex(accessAddr);
    char byteMask = getByteMask(accessAddr);
    is_tainted |= (bool)((mem_taint[idx] & byteMask) != false);
    if (is_tainted) break;
  }

  return (is_tainted);
}
//modified by richard
VOID Setmem_taint(ADDRINT addr, UINT32 size, bool is_tainted, ADDRINT inst,THREADID id)
{
 
  list<TaintSourceEntry>::iterator ptrEntry;
  // Prints the last memory that was tainted and its content
   if (!PropTaint(id))
  {
    return;
  }
  GetLock(&lock,id+1);
  if (is_tainted)
  {
    
     //标记内存区域为污点
    for (UINT32 i = 0; i < size; i ++)
    {
      int accessAddr = addr+i;
      //int _idx = getTableIndex(accessAddr);
      //char _byteMask = getByteMask(accessAddr);
      mem_taint[getTableIndex(accessAddr)] |= getByteMask(accessAddr);
    }
    
    if (Measurement)
      setmem_taint++;
  }
  else//该内存区域漂白
  {

    if (Getmem_taint(addr, size, inst))
    {
        
      //inserted by richard,对于要漂白的原先污染的内存，清除对应在污点源映射表中的项
      for (UINT32 i = 0; i < size; i ++)
      {
          if (!Getmem_taint(addr+i,1,inst))
          {
              continue;
          } 
          ptrEntry =find_if(memTaintSrcTable.begin(), memTaintSrcTable.end(), FindAddrFromList(addr+i));
          //不一定能找到对应的污染源,可能4字节污染的内存中，只有一个字节被污染了，但是这四字节的区域都显示为被污染
          if ((ptrEntry==memTaintSrcTable.end()))
          {
              PrintErr("ptrEntry==memTaintSrcTable.end()","EraseMemTaintSrc",inst);
          }
          

           memTaintSrcTable.erase(ptrEntry);
          

      }
    } 
    
    for (UINT32 i = 0; i < size; i ++)
    {
      int accessAddr = addr+i;
      mem_taint[getTableIndex(accessAddr)] &= (char)(~getByteMask(accessAddr));
    }
  }
  ReleaseLock(&lock);
}
VOID SetMemTaintSource(ADDRINT addr,ADDRINT size,set<int> taintsrc,ADDRINT inst,THREADID id)
{
    TaintSourceEntry taintentry;
    list<TaintSourceEntry>::iterator ptrEntry;
    if (!PropTaint(id))
    {
      return;
    }
    if (!taintsrc.empty())
    {
        GetLock(&lock,id+1);
        //update in 2012-11-1
         //info:check taint degree
         unsigned int imema=taintsrc.size();
        // unsigned int immb=(double)(iTNTBuffLength)*0.2;
         if (iTNTEncryDegree==0)
         {
             SysLog<<"";
         }
         if (imema>iTNTEncryDegree)
         {
             if(TNT_mem_node.addr_start==0)
             {
                 TNT_mem_node.addr_start=addr;
                 TNT_mem_node.addr_end=addr+size;
                 TNT_mem_node.iMaxTntDgr=taintsrc.size();
                 TNT_mem_node.instr.insert(inst);
             }
             else if (TNT_mem_node.addr_end == addr)
             {
                 TNT_mem_node.addr_end=addr+size;
                 TNT_mem_node.iMaxTntDgr=(TNT_mem_node.iMaxTntDgr>taintsrc.size())?TNT_mem_node.iMaxTntDgr:taintsrc.size();
                 TNT_mem_node.instr.insert(inst);
             }
             else //Out Put TNT_memNode and reset it
             { 
                 SysLog << "[HIGH-TNT] " << "PC " << hex << PrintSet(TNT_mem_node.instr).c_str() << " tainting mem "
                     << hex << TNT_mem_node.addr_start << " - " << hex 
                     << (ADDRINT)TNT_mem_node.addr_end<< " Max Taint Degree "<<TNT_mem_node.iMaxTntDgr<<endl << flush;
                 //int length=TNT_mem_node.addr_end-TNT_mem_node.addr_start;
                 //string memdata=printMemdata((char *)TNT_mem_node.addr_start,length,false);
                 //SysLog<<"[TNT_MEM]"<<memdata.c_str()<<endl;
                 //RESET TNT_Mem_Node
                 TNT_mem_node.addr_start=addr;
                 TNT_mem_node.addr_end=addr+size;
                 TNT_mem_node.iMaxTntDgr=taintsrc.size();
                 TNT_mem_node.instr.clear();
                 TNT_mem_node.instr.insert(inst);
             }
         }

        //标记内存区域为污点
        for (UINT32 i = 0; i < size; i ++)
        {
            //如果该地址已经被污染，因此一定要用在Setmem_taint之前
            if(Getmem_taint(addr+i,1,inst))
            {
                ptrEntry =find_if(memTaintSrcTable.begin(), memTaintSrcTable.end(), FindAddrFromList(addr+i));
                //一定能在污染源映射表中找到那一项
                //assert(ptrEntry!=memTaintSrcTable.end());
                if ((ptrEntry==memTaintSrcTable.end()))
                {

                    PrintErr("ptrEntry!=memTaintSrcTable.end()","SetMemTaintSource",inst);   
                    return;
                }
                
                //应该是将原先污染内存覆盖掉
                (*ptrEntry).srcOffsets=taintsrc;
            }
            else
            {
                taintentry.memaddr=addr+i;
                taintentry.srcOffsets=taintsrc;
                //尾插法
                //cerr<<"addr: "<<taintentry.memaddr<<"  offset: "<<*(taintsrc.begin())<<" threadid: "<<PIN_ThreadId()<<endl;
                memTaintSrcTable.insert(memTaintSrcTable.begin(),taintentry);           
            }
        }
         ReleaseLock(&lock);
         
        
    }

}
/************************************************************************/
/* by richard
打印污染指令*/
/************************************************************************/
VOID PrintTaintInstrunction(ADDRINT addr,set<int>& t)
{
  if (!KnobDebug)
  {
    return;
  }
  ADDRINT func=GetRtnAddr(addr);
  if (func>0x20000000)
  {
    //return;
  }
  SysLog << "[TNTINS] " << "PC ：" << hex << addr << " corres  function address："
    <<hex<<func<<endl << flush;
  SysLog<<"[TNTSRC]"<<" PC ：" << hex << addr <<" corres  OFFSET:"<<PrintSet(t)<<endl;


}
/************************************************************************/
/* 获取某段内存所有污点源的集合          
输入:memsrc:内存起始位置
memsz:内存大小
iaddr:指令地址
id:线程ID
返回：集合类型(set)，返回所有污点源偏移的集合
*/
/************************************************************************/
set<int> GetMemTaintSource(ADDRINT memsrc,ADDRINT memsz, ADDRINT iaddr, THREADID id)
{
  list<TaintSourceEntry>::iterator ptrEntry;
  set<int> result;
  for(ADDRINT i=0;i<memsz;i++)
  { 
    //只有包含了污点信息的内存才处理，提升效率，同时，与内存位图保持一致
    if (Getmem_taint(memsrc+i,1,0))
    {
      ptrEntry =find_if(memTaintSrcTable.begin(), memTaintSrcTable.end(), FindAddrFromList(memsrc+i));
      if (ptrEntry==memTaintSrcTable.end())
      {
        PrintErr("ptrEntry!=memTaintSrcTable.end()","GetMemTaintSource",iaddr); 
      } 
      result=Union(result,(*ptrEntry).srcOffsets);
    }
  }
  return result;
}
/************************************************************************
 拷贝内存区域的污点信息
   from:源地址
   to:目的地址
   fromlen:源污点区域的长度
   from_step：源污点区域的粒度（一般为）
   tolen:目标区域长度
   to_step：目标区域粒度
   tid：线程ID
   return被污染内存所有偏移来源
************************************************************************/
set<int> copytaint(ADDRINT from, ADDRINT to, ADDRINT fromlen,  UINT32 from_step, ADDRINT tolen, UINT32 to_step, THREADID tid)
{
  set<int> t;
  //收集最终的偏移信息
  set<int> result;
  for (unsigned int i = 0; i<fromlen && i<tolen;i++)
  {
  t=GetMemTaintSource(from+i*from_step, from_step, 0, tid);
  SetMemTaintSource(to+i*to_step, to_step,t,0,tid);
    Setmem_taint(to+i*to_step, to_step,(!t.empty()), 0,tid);
  result=Union(result,t);
  }
  return result;
}
VOID PIN_FAST_ANALYSIS_CALL HandleRepMov(ADDRINT iaddr, ADDRINT reg_ecx,ADDRINT memsrc, 
                       ADDRINT memsrcsz , ADDRINT memdst, ADDRINT memdstsz,
                       THREADID id)
{
   set<int> t;
   if(GetRegisterTaint(REG_ECX,id,iaddr))
   {
     string info=string("REP ECX tainted with instruction addr 0x")+itoHex(iaddr);
     t=GetRegisterTaintSrc(REG_ECX,id,iaddr);
     //PrintSensiveData(info,t,NUM_TYPE,id);

     t=GetMemTaintSource(memsrc,memsrcsz,iaddr,id);
     if (!t.empty())
     {
       TraceFile<<" REP ECX taint Source: "<<PrintSet(t)<<endl;
     }
     PrintTaintInstrunction(iaddr,t);
   }
   t=copytaint(memsrc, memdst, memsrcsz, 1, memdstsz, 1, id);
   if (!t.empty())
   {
     PrintTaintInstrunction(iaddr,t);
   }
}
inline void
__SetRegisterTaint(bool isTainted, REG r, THREADID id) {
    thread_info1[id].reg_taint[r] = isTainted;
}
//istaint:污染还是漂白，REG r:处理的目标寄存器,id:线程id,iaddr：指令地址
void SetRegisterTaint(bool is_tainted, REG r, THREADID id, ADDRINT iaddr)
{


  //先排除一部分寄存器，如ESP,EIP,EFLAGS
  if (!REG_is_dift(r)&&r!=REG_EFLAGS) return;
  //先打印污染或者漂白信息
  if ( KnobDebug && PropTaint(id))
  {
    //打印污染信息
    if (is_tainted)
      TraceFile << "[TNT] "  << "PC " << hex << iaddr 
      << " tainting reg " << REG_StringShort(r) << endl;
    //打印漂白信息   
  }

  //如果是多媒体扩展寄存器或者是8位的通用寄存器，则先处理
  if (REG_is_xmm(r) || REG_is_mm(r) || REG_is_gr8(r)||r==REG_EFLAGS)
  {
    __SetRegisterTaint(is_tainted,r, id);
    return;
  }
  //剩下的一定是8位或者16位的通用寄存器
  assert (REG_is_gr(r) || REG_is_gr16(r));

  //例如EAX被污染，那么AX，AH,AL，一定被污染，这里可能有误差（过度传播），如果EAX中只有最高字节被污染，那么AH,AL都没被污染，但这种可能性很小
  switch(r)
  {
  case REG_EAX:
    __SetRegisterTaint(is_tainted,REG_EAX, id);
  case REG_AX:
    __SetRegisterTaint(is_tainted,REG_AH, id);
    __SetRegisterTaint(is_tainted,REG_AL, id);
    break;
  case REG_EBX:
    __SetRegisterTaint(is_tainted,REG_EBX, id);
  case REG_BX:
    __SetRegisterTaint(is_tainted,REG_BH, id);
    __SetRegisterTaint(is_tainted,REG_BL, id);
    break;
  case REG_ECX:
    __SetRegisterTaint(is_tainted,REG_ECX, id);
  case REG_CX:
    __SetRegisterTaint(is_tainted,REG_CH, id);
    __SetRegisterTaint(is_tainted,REG_CL, id);
    break;
  case REG_EDX:
    __SetRegisterTaint(is_tainted,REG_EDX, id);
  case REG_DX:
    __SetRegisterTaint(is_tainted,REG_DH, id);
    __SetRegisterTaint(is_tainted,REG_DL, id);
    break;
  case REG_ESI:
    __SetRegisterTaint(is_tainted,REG_ESI, id);
  case REG_SI:
    __SetRegisterTaint(is_tainted,REG_SI, id);
    break;
  case REG_EDI:
    __SetRegisterTaint(is_tainted,REG_EDI, id);
  case REG_DI:
    __SetRegisterTaint(is_tainted,REG_DI, id);
    break;
  case REG_EBP:
    __SetRegisterTaint(is_tainted,REG_EBP, id);
  case REG_BP:
    __SetRegisterTaint(is_tainted,REG_BP, id);
    break;
    /*
    case REG_ESP:
    __SetRegisterTaint(is_tainted,REG_ESP);
    case REG_SP:
    __SetRegisterTaint(is_tainted,REG_SP);
    break;
    */
  default:
    assert(0);
  }
}
inline void 
__SetRegisterTaintSrc(set<int> taintsrc, REG r, THREADID id) {
  //thread_info[id].reg_taintsrc_table[r]=taintsrc;
  thread_info1[id].ptaintsrc_table[r]=taintsrc;
}
//istaint:污染还是漂白，REG r:处理的目标寄存器,id:线程id,iaddr：指令地址
void SetRegisterTaintSrc(set<int> taintsrc, REG r, THREADID id, ADDRINT iaddr)
{
  //先排除一部分寄存器，如ESP,EIP,EFLAGS
  if (!REG_is_dift(r)&&r!=REG_EFLAGS) return;

  //如果是多媒体扩展寄存器或者是8位的通用寄存器，则先处理
  if (REG_is_xmm(r) || REG_is_mm(r) || REG_is_gr8(r)|| r==REG_EFLAGS)
  {
    __SetRegisterTaintSrc(taintsrc,r, id);
    return;
  }
  //剩下的一定是32位或者16位的通用寄存器
  assert (REG_is_gr(r) || REG_is_gr16(r));

  //例如EAX被污染，那么AX，AH,AL，一定被污染，这里可能有误差（过度传播），如果EAX中只有最高字节被污染，那么AH,AL都没被污染，但这种可能性很小
  switch(r)
  {
  case REG_EAX:
    __SetRegisterTaintSrc(taintsrc,REG_EAX, id);
  case REG_AX:
    __SetRegisterTaintSrc(taintsrc,REG_AH, id);
    __SetRegisterTaintSrc(taintsrc,REG_AL, id);
    break;
  case REG_EBX:
    __SetRegisterTaintSrc(taintsrc,REG_EBX, id);
  case REG_BX:
    __SetRegisterTaintSrc(taintsrc,REG_BH, id);
    __SetRegisterTaintSrc(taintsrc,REG_BL, id);
    break;
  case REG_ECX:
    __SetRegisterTaintSrc(taintsrc,REG_ECX, id);
  case REG_CX:
    __SetRegisterTaintSrc(taintsrc,REG_CH, id);
    __SetRegisterTaintSrc(taintsrc,REG_CL, id);
    break;
  case REG_EDX:
    __SetRegisterTaintSrc(taintsrc,REG_EDX, id);
  case REG_DX:
    __SetRegisterTaintSrc(taintsrc,REG_DH, id);
    __SetRegisterTaintSrc(taintsrc,REG_DL, id);
    break;
  case REG_ESI:
    __SetRegisterTaintSrc(taintsrc,REG_ESI, id);
  case REG_SI:
    __SetRegisterTaintSrc(taintsrc,REG_SI, id);
    break;
  case REG_EDI:
    __SetRegisterTaintSrc(taintsrc,REG_EDI, id);
  case REG_DI:
    __SetRegisterTaintSrc(taintsrc,REG_DI, id);
    break;
  case REG_EBP:
    __SetRegisterTaintSrc(taintsrc,REG_EBP, id);
  case REG_BP:
    __SetRegisterTaintSrc(taintsrc,REG_BP, id);
    break;
  default:
    assert(0);
  }
}
VOID PIN_FAST_ANALYSIS_CALL RegisterUntaint(ADDRINT iaddr, UINT32 regid, THREADID id)
{
  REG reg;
      
  if (regid < (NR_REG(REG_GR)))
    reg = static_cast<REG>(REG_GR_BASE + regid);
  else
    reg = static_cast<REG>(REG_AL + regid - NR_REG(REG_GR));
  //modified by richard
  set<int> t;
  SetRegisterTaintSrc(t,reg,id,iaddr);//将源污点源清空
  SetRegisterTaint(false, reg, id, iaddr);

}
//内存漂白
VOID PIN_FAST_ANALYSIS_CALL MemUntaint(ADDRINT iaddr, ADDRINT memaddr, ADDRINT memsz, THREADID id)
{
  Setmem_taint(memaddr, memsz, false, iaddr, id); 
}
//仅仅mov用到，例如REP,CALL [0x1234]等
//将某一内存区域的污点信息拷贝到另一内存区域中
//iaddr:指令地址，memsrc：源地址，memsrcsz：源内存大小,memdst：目标地址,memdstsz：目标大小
VOID PIN_FAST_ANALYSIS_CALL DoPropMemtoMem(ADDRINT iaddr, ADDRINT memsrc, 
                        ADDRINT memsrcsz , ADDRINT memdst, ADDRINT memdstsz,
                        THREADID id)
{
  //count_profile(iaddr);
  //modified by richhard
  set<int> t=copytaint(memsrc, memdst, memsrcsz, 1, memdstsz, 1, id);
  if (!t.empty())
  PrintTaintInstrunction(iaddr,t);
}
/************************************************************************/
/* 基址内存寻址-》寄存器的污点传播                                      */
/************************************************************************/
/*iaddr:指令地址  memsrc:读内存地址 memsz:读内存的大小 reg_baseid:基址寄存器（源） reg_indexid:索引寄存器（源） 
reg_dstid:目标寄存器*/
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL DoPropMemBaseIndextoReg(ADDRINT iaddr, ADDRINT memsrc, 
                        ADDRINT memsz , UINT32 reg_baseid, UINT32 reg_indexid, UINT32 reg_dstid, THREADID id)
{
  //count_profile(iaddr);
  set<int> t;
  //源基址寄存器或者索引寄存器有一个被污染（尽管内存可能没有被污染），那么目标寄存器也被污染
  if (GetRegisterTaint(static_cast<REG>(reg_indexid), id, iaddr) ||GetRegisterTaint(static_cast<REG>(reg_baseid), id, iaddr) ) // index is tainted
  { 
    //modified my richhard
    t=Union(GetRegisterTaintSrc(static_cast<REG>(reg_indexid), id, iaddr),GetRegisterTaintSrc(static_cast<REG>(reg_baseid),id,iaddr));   
    SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);
    SetRegisterTaint(true, static_cast<REG>(reg_dstid), id, iaddr);
   //print taint ins
    PrintTaintInstrunction(iaddr,t);
   
  }
  else
  {
  t=GetMemTaintSource(memsrc, memsz, iaddr, id);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid), id, iaddr);
    SetRegisterTaint((!t.empty()), static_cast<REG>(reg_dstid), id, iaddr);
  //print taint ins
  if(!t.empty())
    PrintTaintInstrunction(iaddr,t);
  //modified by richhard
  }
}
//只有mov调用，寄存器宽度和内存宽度一定相同
VOID PIN_FAST_ANALYSIS_CALL DoPropMemtoReg(ADDRINT iaddr, ADDRINT memsrc, 
                        ADDRINT memsz , UINT32 reg_dstid, THREADID id)
{       

  
  //count_profile(iaddr);  
  set<int> t;
  #if DEBUG_MOV
  TraceFile<<"Prop Mem To Reg With PC: "<<iaddr<<" src addr: "<<memsrc<<" memsize: "<<memsz<<" whether taint: "<<Getmem_taint(memsrc, memsz, iaddr, id)<<endl;
  #endif
  // by richard 
  t=GetMemTaintSource(memsrc, memsz, iaddr, id);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid), id, iaddr);
  SetRegisterTaint((!t.empty()), static_cast<REG>(reg_dstid), id, iaddr);
 
  if(!t.empty())
    //print taint ins
    PrintTaintInstrunction(iaddr,t);

}
//返回mask中为1的个数
static UINT32 MaxNumMaskReg(UINT32 mask)
{
  UINT32 cnt = 0;
  for (UINT32 i = 0; i < 32; i++)
    if (mask & (1<<i)) cnt++;
  
  return cnt;
}
static UINT32 MaskReg(UINT32 mask, UINT32 idx)
{
  UINT32 next = mask & -int(mask);
  UINT32 regid;

  assert(mask && idx < MaxNumMaskReg(mask));

  for (UINT32 i = 0; i < idx; i++)
  {
    mask &= ~next;
    next = mask & -int(mask);
  }

  assert(mask);
  for (regid = 0; (UINT32) (1 << regid) != next; regid++);

  return regid;
}
//liu 925
/************************************************************************/
//R->M
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR_M1(ADDRINT iaddr, 
                  string *disas,
                  UINT32 reg_read, 
                  ADDRINT mem_write,
                  ADDRINT mem_write_sz,THREADID id)
{
  bool is_tainted = false;
  REG reg;
  set<int> taintsrc; 
  reg = static_cast<REG>(reg_read);
    
  taintsrc=GetRegisterTaintSrc(reg,id,iaddr);
  is_tainted |= (!taintsrc.empty());
  if (is_tainted)
  {
    //print taint ins
    TraceFile <<" liuR_M "<<hex<<iaddr<<" "<<*disas<<" reg: "<<REG_StringShort(reg)<<" mem: "<<mem_write<<" memsize: "<<mem_write_sz<<endl;  
  }

  
  return;
}
VOID PIN_FAST_ANALYSIS_CALL liuR_M(ADDRINT iaddr, 
                  string *disas,
                  UINT32 reg_read, 
                  ADDRINT mem_write,
                  ADDRINT mem_write_sz,THREADID id)
{
  bool is_tainted = false;
  REG reg;
  set<int> taintsrc; 
  reg = static_cast<REG>(reg_read);
    
  taintsrc=GetRegisterTaintSrc(reg,id,iaddr);
  is_tainted |= (!taintsrc.empty());
  if (is_tainted)
  {
    //print taint ins
    TraceFile <<" liuR_M "<<hex<<iaddr<<" "<<*disas<<" reg: "<<REG_StringShort(reg)<<" mem: "<<mem_write<<" memsize: "<<mem_write_sz<<endl;  
  
  }

  if (mem_write != iaddr)
  { 
   //modified by richhard
    if(is_tainted)
    {
    
      SetMemTaintSource(mem_write, mem_write_sz,taintsrc, iaddr, id);
    
    }
    Setmem_taint(mem_write, mem_write_sz, is_tainted, iaddr, id);
  }

  
}
VOID PIN_FAST_ANALYSIS_CALL liuM_R(ADDRINT iaddr, 
                  string *disas,
                  UINT32 reg_write, 
                  ADDRINT mem_read,
                  ADDRINT mem_read_sz,THREADID id)
{
  bool is_tainted = false;
  REG reg;
  set<int> taintsrc; 
  reg = static_cast<REG>(reg_write);
  taintsrc=GetMemTaintSource(mem_read,mem_read_sz,iaddr,id);
  //taintsrc=GetRegisterTaintSrc(reg,id,iaddr);
  is_tainted |= (!taintsrc.empty());
  if (is_tainted)
  {
    //print taint ins
    TraceFile <<" liuM_R "<<hex<<iaddr<<" "<<*disas<<" reg: "<<REG_StringShort(reg)<<" mem: "<<mem_read<<" memsize: "<<mem_read_sz<<endl;  
    SetRegisterTaintSrc(taintsrc,reg,id,iaddr);
  }

}
/************************************************************************/
/* iddr:指令地址  gr_read:读寄存器的集合，位图表示 gr_write：写寄存器集合，位图表示
   mem_read1:读的第一个内存地址，mem_read2:读的第二个内存的地址,mem_read_size：读内存的大小，mem_write:所写内存的地址，
   mem_write_sz:写内存的大小*///如：pop ebx
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL DoPropNoExtReg(ADDRINT iaddr, UINT32 gr_read, 
                   UINT32 gr_write, ADDRINT mem_read1,
                   ADDRINT  mem_read2, ADDRINT mem_read_sz, ADDRINT mem_write, 
                   ADDRINT mem_write_sz,UINT32  eflags_wt ,THREADID id)
{
  bool is_tainted = false;
  REG reg;
  set<int> taintsrc;
  

  /* Read in the tags of all register read operands -- 
   * full general purpose regs, partial general purpose regs,
   * mm regs, and xmm regs
   */
  //count_profile(iaddr);
  //第一步，查看所有读的集合（包括寄存器，内存）是否有被污染的。
  //查看是否读的寄存器集合中有被污染的
  for (UINT32 i = 0; i < 32; i++)
  {
    if (gr_read & (1<<i))
    {
      if (i < NR_REG(REG_GR))
        reg = static_cast<REG> (REG_GR_BASE + i);
      else
        reg = static_cast<REG> (REG_AL + i - NR_REG(REG_GR));
    //modified by richhard
    taintsrc=Union(taintsrc,GetRegisterTaintSrc(reg,id,iaddr));
    is_tainted |= (!taintsrc.empty());

    
    }
  }
  //查看是否有读的内存被污染的，所读内存地址不是该指令所在地址
  if (mem_read1 != iaddr)
  {
  //modified by richhard
  taintsrc=Union(taintsrc,GetMemTaintSource(mem_read1, (UINT32)mem_read_sz, iaddr, id));
    is_tainted |= (!taintsrc.empty());  
  }
  if (mem_read2 != iaddr)
  {
  //modified by richhard
  taintsrc=Union(taintsrc,GetMemTaintSource(mem_read2, (UINT32)mem_read_sz, iaddr, id));
    is_tainted |=(!taintsrc.empty()); 
  }

  if (is_tainted)
  {
    //print taint ins
    PrintTaintInstrunction(iaddr,taintsrc);
  }

  //第二步，下面对所有写的寄存器，内存进行污点传播，如果读集合中有被污染的，那么写集合也都被污染
  /* Step 2 - now propagate to all registers in write set, and
   * written bytes of memory (if any) 
   */

  for (UINT32 i = 0; i < 32; i++)
  {
    if (gr_write & (1<<i))
    {
      if (i < NR_REG(REG_GR))
        reg = static_cast<REG> (REG_GR_BASE + i);
      else
        reg = static_cast<REG> (REG_AL + i - NR_REG(REG_GR));
    SetRegisterTaintSrc(taintsrc,reg,id,iaddr);
      SetRegisterTaint(is_tainted,reg,id,iaddr);
    }
  }
  if (mem_write != iaddr)
  { 
   //modified by richhard
    if(is_tainted)
  {
    if(taintsrc.empty())
      PrintErr("taint source empty","DoPropNoExtReg",iaddr);
    SetMemTaintSource(mem_write, mem_write_sz,taintsrc, iaddr, id);
    
  }
    Setmem_taint(mem_write, mem_write_sz, is_tainted, iaddr, id);
  }

  //eflags
  if (eflags_wt)
  {
    
   
    SetRegisterTaintSrc(taintsrc,static_cast<REG>(REG_EFLAGS),id,iaddr);
    SetRegisterTaint(is_tainted,
      static_cast<REG>(REG_EFLAGS),id,iaddr);
  }
}
/************************************************************************/
/* 读了两个寄存器，R->R,有污点的寄存器污点信息复制到目标寄存器中        *///如add eax,ebx
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL DoPropRegR2(ADDRINT iaddr, UINT32 reg_src1id, UINT32 reg_src2id,
                        UINT32 reg_dstid,UINT32  eflags_wt,THREADID id)
{
  //count_profile(iaddr); 
  //by richard，如果两个操作数进行了运算，那么目的操作数的污点源一定是这两个操作数污点源的并
  set<int> t=Union(GetRegisterTaintSrc(static_cast<REG>(reg_src1id), id, iaddr),GetRegisterTaintSrc(static_cast<REG>(reg_src2id), id, iaddr));
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);

  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_src1id), id, iaddr)
    | GetRegisterTaint(static_cast<REG>(reg_src2id), id, iaddr),
    static_cast<REG>(reg_dstid),id,iaddr);

  if (eflags_wt)
  {
    SetRegisterTaintSrc(t,static_cast<REG>(REG_EFLAGS),id,iaddr);

    SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_src1id), id, iaddr)
      | GetRegisterTaint(static_cast<REG>(reg_src2id), id, iaddr),
      static_cast<REG>(REG_EFLAGS),id,iaddr);
  }
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liu0_R(ADDRINT iaddr,  UINT32 reg_dstid, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t;
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);

  SetRegisterTaint(false,static_cast<REG>(reg_dstid),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR_R(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);

  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr),static_cast<REG>(reg_dstid),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR_R2(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid,UINT32 reg_dstid1, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid1),id,iaddr);
  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr),static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr),static_cast<REG>(reg_dstid1),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR2_R2(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid,UINT32 reg_srcid1, UINT32 reg_dstid1, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  t = Union(t,GetRegisterTaintSrc(static_cast<REG>(reg_srcid1),id,iaddr));
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid1),id,iaddr);
  bool s = GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr)||GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid1),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR2_R3(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid,UINT32 reg_srcid1, UINT32 reg_dstid1, UINT32 reg_dstid2, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  t = Union(t,GetRegisterTaintSrc(static_cast<REG>(reg_srcid1),id,iaddr));
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid1),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid2),id,iaddr);

  bool s = GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr)||GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid1),id,iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid2),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR2_EXCH(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  set<int> t1=GetRegisterTaintSrc(static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaintSrc(t1,static_cast<REG>(reg_srcid),id,iaddr);
  bool s=GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr);
  bool s1=GetRegisterTaint(static_cast<REG>(reg_dstid), id, iaddr);
  SetRegisterTaint(s,static_cast<REG>(reg_dstid),id,iaddr);
  SetRegisterTaint(s1,static_cast<REG>(reg_srcid),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR2_FUCOMI(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid, THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  set<int> t1=Union(t,GetRegisterTaintSrc(static_cast<REG>(reg_dstid),id,iaddr));
  SetRegisterTaintSrc(t1,static_cast<REG>(REG_EFLAGS),id,iaddr);
  
  bool s=GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr);
  bool s1=GetRegisterTaint(static_cast<REG>(reg_dstid), id, iaddr);
  SetRegisterTaint(s||s1,static_cast<REG>(REG_EFLAGS),id,iaddr);
 
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL liuR2_R(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid, UINT32 reg_srcid2,THREADID id)
{       
  //count_profile(iaddr);  
  //REG reg_read=static_cast<REG>(reg_srcid);
  //REG reg_write=static_cast<REG>(reg_dstid);
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  t=Union(t,GetRegisterTaintSrc(static_cast<REG>(reg_srcid2),id,iaddr));
  //if(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr)||GetRegisterTaint(static_cast<REG>(reg_srcid2), id, iaddr))
  //{
   // TraceFile << " liuR2_R "<< hex << iaddr << endl;
  //}
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);

  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr)||GetRegisterTaint(static_cast<REG>(reg_srcid2), id, iaddr),static_cast<REG>(reg_dstid),id,iaddr);
  
}
/************************************************************************/
/* 读了一个寄存器,R->R，只需把污点信息复制到目标寄存器                  */
/************************************************************************/
VOID PIN_FAST_ANALYSIS_CALL DoPropRegR1(ADDRINT iaddr, UINT32 reg_srcid, UINT32 reg_dstid, UINT32  eflags_wt,THREADID id)
{       
  //count_profile(iaddr);  
  set<int> t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  SetRegisterTaintSrc(t,static_cast<REG>(reg_dstid),id,iaddr);

  SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr),
    static_cast<REG>(reg_dstid),id,iaddr);
  //IMPOSSIBLE???
  if (eflags_wt)
  {
    SetRegisterTaintSrc(t,static_cast<REG>(REG_EFLAGS),id,iaddr);

    SetRegisterTaint(GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr),
      static_cast<REG>(REG_EFLAGS),id,iaddr);
  }
}
/* See below for an why we're comparing mem_read* and mem_write to iaddr */
VOID PIN_FAST_ANALYSIS_CALL DoProp(ADDRINT iaddr, UINT32 gr_read, UINT32 xt_read,
                   UINT32 gr_write, UINT32 xt_write, ADDRINT mem_read1,
                   ADDRINT mem_read2, ADDRINT mem_read_sz, ADDRINT mem_write, 
                   ADDRINT mem_write_sz, THREADID id)
{
  bool is_tainted = false;
  REG reg;        
    set<int> taintsrc;
  //if (iaddr==0x60d18e)
  //{
    //TraceFile<<"testmyinstrInHook"<<endl;
  //}

  /* Read in the tags of all register read operands -- 
  * full general purpose regs, partial general purpose regs,
  * mm regs, and xmm regs
  */
  //count_profile(iaddr);
  for (UINT32 i = 0; i < 32; i++)
  {
    if (gr_read & (1<<i))
    {
      if (i < NR_REG(REG_GR))
        reg = static_cast<REG> (REG_GR_BASE + i);
      else
        reg = static_cast<REG> (REG_AL + i - NR_REG(REG_GR));
      //modified by richhard
      taintsrc=Union(taintsrc,GetRegisterTaintSrc(reg,id,iaddr));
      is_tainted |= (!taintsrc.empty());
    }
  }
  for (UINT32 i = 0; i < 32; i++)
  {
    if (xt_read & (1<<i))
    {
      if (i < NR_REG(REG_MM))
        reg = static_cast<REG> (REG_MM_BASE + i);
      else
        reg = static_cast<REG> (REG_XMM_BASE + i - NR_REG(REG_MM));
      //modified by richhard
      taintsrc=Union(taintsrc,GetRegisterTaintSrc(reg,id,iaddr));
      is_tainted |= (!taintsrc.empty());
    }
  }
  //查看是否有读的内存被污染的，所读内存地址不是该指令所在地址
  if (mem_read1 != iaddr)
  {
    //modified by richhard
    taintsrc=Union(taintsrc,GetMemTaintSource(mem_read1, (UINT32)mem_read_sz, iaddr, id));
    is_tainted |= (!taintsrc.empty());  
  }
  if (mem_read2 != iaddr)
  {
    //modified by richhard
    taintsrc=Union(taintsrc,GetMemTaintSource(mem_read2, (UINT32)mem_read_sz, iaddr, id));
    is_tainted |=(!taintsrc.empty()); 
  }
  /* Step 2 - now propagate to all registers in write set, and
  * written bytes of memory (if any) 
  */
  for (UINT32 i = 0; i < 32; i++)
  {
    if (gr_write & (1<<i))
    {
      if (i < NR_REG(REG_GR))
        reg = static_cast<REG> (REG_GR_BASE + i);
      else
        reg = static_cast<REG> (REG_AL + i - NR_REG(REG_GR));

      SetRegisterTaintSrc(taintsrc,reg,id,iaddr);
      SetRegisterTaint(is_tainted,reg,id,iaddr);
    }
  }
  for (UINT32 i = 0; i < 32; i++)
  {
    if (xt_write & (1<<i))
    {
      if (i < NR_REG(REG_MM))
        reg = static_cast<REG> (REG_MM_BASE + i);
      else
        reg = static_cast<REG> (REG_XMM_BASE + i - NR_REG(REG_MM));
      SetRegisterTaintSrc(taintsrc,reg,id,iaddr);
      SetRegisterTaint(is_tainted,reg,id,iaddr);
    }
  }
  if (mem_write != iaddr)
  {
    if(is_tainted)
    {
      if(taintsrc.empty())
        PrintErr("taint source empty","DoPropReg",iaddr);
      SetMemTaintSource(mem_write, mem_write_sz,taintsrc, iaddr, id);
    }
    Setmem_taint(mem_write, mem_write_sz, is_tainted, iaddr, id);
  }
}

//将寄存器污染信息拷贝到目标内存中，仅仅MOV用
//iaddr:指令地址
//reg_srcid:寄存器编号
//memsrc：目标内存地址
//memsz:目标内存大小
VOID PIN_FAST_ANALYSIS_CALL DoPropRegtoMem(ADDRINT iaddr, UINT32 reg_srcid, ADDRINT memsrc, 
                        ADDRINT memsz , THREADID id)
{
  //count_profile(iaddr);
  set<int> t;
  #if DEBUG_MOV
  TraceFile<<"Prop Reg To Mem With PC: "<<iaddr<<"src register:  "<<REG_StringShort(static_cast<REG>(reg_srcid))<<" memdst: "<<memsrc<<" register whether taint: "<<GetRegisterTaint(static_cast<REG>(reg_srcid), id, iaddr)<<endl;
  #endif
  t=GetRegisterTaintSrc(static_cast<REG>(reg_srcid),id,iaddr);
  SetMemTaintSource(memsrc,memsz,t,iaddr,id);
  Setmem_taint(memsrc, memsz,(!t.empty()), iaddr, id);
  if(!t.empty())
    //print taint ins
    PrintTaintInstrunction(iaddr,t);
}
/************************************************************************/
/* Mov 指令的污点传播               INS_Address(ins)                                    */
/************************************************************************/
static bool Instrument_FXCH(INS ins) {
  // handle rep operations first, as a special case，首先处理REP前缀的MOV指令.一定是mem->mem
 //TraceFile <<" FXCH "<<INS_Disassemble(ins)<<endl;
 uint32_t r1 = INS_OperandRead(ins, 0);
 uint32_t r2 = INS_OperandRead(ins, 1);
 if(r1!= REG_INVALID() && r2!= REG_INVALID())
 {
    IFCOND(ins);
    INS_InsertThenCall(ins, 
      IPOINT_BEFORE, 
      AFUNPTR(liuR2_EXCH), 
      IARG_FAST_ANALYSIS_CALL,      
      IARG_INST_PTR, 
      IARG_ADDRINT, r1,
      IARG_ADDRINT, r2,
      IARG_THREAD_ID,
      IARG_END);
 }

  
  return true;
}
/************************************************************************/
/* Mov 指令的污点传播               INS_Address(ins)                                    */
/************************************************************************/
static bool Instrument_FUCOMI(INS ins) {
  // handle rep operations first, as a special case，首先处理REP前缀的MOV指令.一定是mem->mem
 //TraceFile <<" FXCH "<<INS_Disassemble(ins)<<endl;
 uint32_t r1 = INS_OperandRead(ins, 0);
 uint32_t r2 = INS_OperandRead(ins, 1);
 if(r1!= REG_INVALID() && r2!= REG_INVALID())
 {
    IFCOND(ins);
    INS_InsertThenCall(ins, 
      IPOINT_BEFORE, 
      AFUNPTR(liuR2_FUCOMI), 
      IARG_FAST_ANALYSIS_CALL,      
      IARG_INST_PTR, 
      IARG_ADDRINT, r1,
      IARG_ADDRINT, r2,
      IARG_THREAD_ID,
      IARG_END);
 }

  
  return true;
}
/************************************************************************/
/* Mov 指令的污点传播               INS_Address(ins)                                    */
/************************************************************************/
static bool Instrument_MOV(INS ins) {
  // handle rep operations first, as a special case，首先处理REP前缀的MOV指令.一定是mem->mem
  if (!REMOVE_REP && INS_RepPrefix(ins)) {// rep operations only make sense as mem -> mem
    //by richhard
#if RECORD_REP_COUNT
    IFCOND(ins);
    INS_InsertThenCall(ins, 
      IPOINT_BEFORE, 
      AFUNPTR(HandleRepMov), 
      IARG_FAST_ANALYSIS_CALL,      
      IARG_INST_PTR, 
      IARG_REG_VALUE,
        REG_ECX,
      IARG_MEMORYREAD_EA, 
      IARG_MEMORYREAD_SIZE,
      IARG_MEMORYWRITE_EA,
      IARG_MEMORYWRITE_SIZE,
      IARG_THREAD_ID,
      IARG_END);
#else
    IFCOND(ins);
    INS_InsertThenCall(ins, 
      IPOINT_BEFORE, 
      AFUNPTR(DoPropMemtoMem), 
      IARG_FAST_ANALYSIS_CALL,      
      IARG_INST_PTR, 
      IARG_MEMORYREAD_EA, 
      IARG_MEMORYREAD_SIZE,
      IARG_MEMORYWRITE_EA,
      IARG_MEMORYWRITE_SIZE,
      IARG_THREAD_ID,
      IARG_END);
#endif
    
    return true;
  }

  if (REMOVE_MEM_ADDRESSING)
    return false;
   /************************************************************************/
   /*    //源(INS_OperandIsReg(ins, 1))是寄存器                            */
   /************************************************************************/
  if(INS_OperandIsReg(ins, 1)) {
   //源是寄存器，目标是寄存器
    if (INS_OperandIsReg(ins, 0)) { //reg->reg
      IFCOND(ins); 
      INS_InsertThenCall(ins, 
        IPOINT_BEFORE, 
        AFUNPTR(DoPropRegR1), 
        IARG_FAST_ANALYSIS_CALL,
        IARG_INST_PTR,
        IARG_ADDRINT, INS_OperandReg(ins, 1), //src reg
        IARG_ADDRINT, INS_OperandReg(ins, 0), //dst reg
    IARG_ADDRINT,0,
        IARG_THREAD_ID,
        IARG_END);
    }
  //源是寄存器，目标是内存
  else if(INS_OperandIsMemory(ins, 0)) { //reg->mem
      if(!INS_IsMemoryWrite(ins)) return false;//如果没有写内存，那么一定没有污点传播
      IFCOND(ins); 
      INS_InsertThenCall(ins, 
        IPOINT_BEFORE, 
        AFUNPTR(DoPropRegtoMem), 
        IARG_FAST_ANALYSIS_CALL,      
        IARG_INST_PTR, 
        IARG_ADDRINT, INS_OperandReg(ins, 1), //src:reg
        IARG_MEMORYWRITE_EA, //写内存的地址
        IARG_MEMORYWRITE_SIZE,//所写内存的大小
        IARG_THREAD_ID,
        IARG_END);
    }
  else {
      SysLog << "[ERR] " << __func__ << "Unknown operand 0 type" 
        << INS_Disassemble(ins) << endl;
      return false;
    }
  }

  /************************************************************************/
  /*  //源（INS_OperandIsMemory(ins, 1)）是内存*/
  /************************************************************************/
  if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) {//源是内存，那么一定有内存读
      SysLog << "[ERR] no read!" << endl;
      return false;
    }
  //目标是寄存器
    if (INS_OperandIsReg(ins, 0)) { //mem -> reg //目标(INS_OperandIsReg(ins, 0))是寄存器
    // no index reg，源是内存，目标是寄存器，源内存没有用索引寄存器寻址
      if (INS_OperandMemoryIndexReg(ins, 1) == REG_INVALID()) {
        IFCOND(ins);
        INS_InsertThenCall(ins,
          IPOINT_BEFORE,
          AFUNPTR(DoPropMemtoReg), 
          IARG_FAST_ANALYSIS_CALL,      
          IARG_INST_PTR, //指令地址
          IARG_MEMORYREAD_EA, //所读内存地址
          IARG_MEMORYREAD_SIZE,//所读内存大小
          IARG_ADDRINT, INS_OperandReg(ins, 0),//目标寄存器 
          IARG_THREAD_ID,
          IARG_END);
      } else {
     //源是内存，目标是寄存器，源内存用索引寄存器寻址
        // maybe creating false negatives with IE,IE中可能会漏报
        // return false;
        IFCOND(ins);
        INS_InsertThenCall(ins,
          IPOINT_BEFORE,
          AFUNPTR(DoPropMemBaseIndextoReg), 
          IARG_FAST_ANALYSIS_CALL,      
          IARG_INST_PTR, 
          IARG_MEMORYREAD_EA, //源内存读地址
          IARG_MEMORYREAD_SIZE,//源内存读的大小
          IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),//源内存基地址寄存器
          IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),//源内存索引寄存器
          IARG_ADDRINT, INS_OperandReg(ins, 0), //目标寄存器
          IARG_THREAD_ID,
          IARG_END);
      }
    }
  //源是内存，目标是内存
  else if(INS_OperandIsMemory(ins, 0)) { // mem -> mem, is this even possible?
      //return false; // this instrumentation CRASHES IE（会导致IE崩溃）
      IFCOND(ins);
      INS_InsertThenCall(ins, 
        IPOINT_BEFORE, 
        AFUNPTR(DoPropMemtoMem), 
        IARG_FAST_ANALYSIS_CALL,      
        IARG_INST_PTR, 
        IARG_MEMORYREAD_EA, 
        IARG_MEMORYREAD_SIZE,
        IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE,
        IARG_THREAD_ID,
        IARG_END);
    }
  }
  /************************************************************************/
  /*     //源是立即数                                                     */
  /************************************************************************/
  if (INS_OperandIsImmediate(ins, 1)) { //imm src
  //目标是寄存器
    if (INS_OperandIsReg(ins, 0)) { // imm -> reg
      IFCOND(ins);
      INS_InsertThenCall(ins, 
        IPOINT_BEFORE, 
        AFUNPTR(RegisterUntaint), //直接漂白
        IARG_FAST_ANALYSIS_CALL, 
        IARG_INST_PTR,
        IARG_ADDRINT, INS_OperandReg(ins, 0), //目标寄存器
        IARG_THREAD_ID, 
        IARG_END);
    }
  //目标是内存
  else if (INS_OperandIsMemory(ins, 0)) {
      IFCOND(ins);
      INS_InsertThenCall(ins, 
        IPOINT_BEFORE, 
        AFUNPTR(MemUntaint),
        IARG_FAST_ANALYSIS_CALL, 
        IARG_INST_PTR, 
        IARG_MEMORYWRITE_EA, 
        IARG_MEMORYWRITE_SIZE, 
        IARG_THREAD_ID, 
        IARG_END);
    }
  }
  return true;
}
void InitInstr() {
  for(int i = 0; i < XED_ICLASS_LAST; i++)
  {
    instrument_functions[i] = &UnimplementedInstruction;
  }

  instrument_functions[XED_ICLASS_MOV] = &Instrument_MOV; //61

  instrument_functions[XED_ICLASS_MOVSB] = &Instrument_MOV; //81
  instrument_functions[XED_ICLASS_MOVSW] = &Instrument_MOV; //82
  instrument_functions[XED_ICLASS_MOVSD] = &Instrument_MOV; //83
  instrument_functions[XED_ICLASS_MOVZX] = &Instrument_MOV; //236
  instrument_functions[XED_ICLASS_MOVSX] = &Instrument_MOV; //378
  //instrument_functions[XED_ICLASS_MOVSX] = &Instrument_MOV; //378
  //instrument_functions[XED_ICLASS_FXCH] = &Instrument_FXCH; //378
  //instrument_functions[XED_ICLASS_FUCOMI] = &Instrument_FUCOMI; //378
  
}
//liu 911

list <branch_st> g_bbls;
char buf_file_addrs[50];
// maximum size of the buffer.
ADDRINT WriteBlock(THREADID threadid,ADDRINT addr,bool taken)
{
  ofstream fpaddrs;
  GetLock(&lock, threadid+1);
  branch_st tmp_branch;
  tmp_branch.addr = addr;
  tmp_branch.taken = taken;
  g_bbls.push_back(tmp_branch);
  
  //cerr<<addr<<" jnz addr!!!!!!!!!!!!!!! "<<g_bbls.size()<<endl;
  if(g_bbls.size() > 1000)
  {
    
        fpaddrs.open(buf_file_addrs,ios::app);
        list<branch_st>::iterator iter;

        //1208/////////////////////////////////////////////////\C9\FA\B3\C9assist.txt
        for(iter=g_bbls.begin();iter!=g_bbls.end();++iter)
        { 
            fpaddrs<<hex<<iter->addr<<" "<<iter->taken<<endl;
        }
        
        fpaddrs.close();
        g_bbls.clear();
  }
  //g_bbls.insert(addr);
  ReleaseLock(&lock);
  return 1;
}
//liu 1012
VOID  CheckConditionalJMP(ADDRINT iaddr,THREADID tid,bool taken,ADDRINT target)
{
  WriteBlock(tid,iaddr,taken);
  
  if(GetRegisterTaint(REG_EFLAGS, tid, iaddr))
  {
    cout<< "[HIGH-TNT_JMP] " << "PC " << hex <<iaddr <<endl;
    SysLog << "[HIGH-TNT_JMP] " << "PC " << hex <<iaddr <<endl;
  }
  return;
  
}
//对sub a,a；xor a,a形式的指令进行寄存器漂白
static bool UntaintXorSub(INS ins)
{
  REG reg = REG_INVALID();
  bool taint_clear = true;
  ADDRINT iaddr = INS_Address(ins);
        
  // It either reads or writes registers
  if (!INS_MaxNumRRegs(ins) || !INS_MaxNumWRegs(ins))
    taint_clear = false;

  for(UINT32 i=0; i < INS_MaxNumRRegs(ins); i++)
  {
    if (!REG_is_dift(INS_RegR(ins,i)))
      taint_clear = false;
    if (reg == REG_INVALID())
      reg = INS_RegR(ins,i);
    else if (reg != INS_RegR(ins,i))
      taint_clear = false;
  }
  // reg is the first register that is a dift register if taint_clear is false
  for(UINT32 i=0; i < INS_MaxNumWRegs(ins); i++)
  {
    if (!REG_is_dift(INS_RegW(ins,i)))
    {
      if (INS_RegW(ins,i) == REG_EFLAGS)
        continue;
      else
        taint_clear = false;
    }
    else if (reg != INS_RegW(ins,i))
      taint_clear = false;
  }
  if (taint_clear)
  {
    /* Okay we know that the source/dest registers are OK 
    * Now just make sure there aren't any memory or 
    * constant operands and we can untaint...
    */
    for(UINT32 i=0; i < INS_OperandCount(ins); i++)
    {
      if (INS_OperandIsMemory(ins, i))
        taint_clear = false;
      else if (INS_OperandIsImmediate(ins,i))
        taint_clear = false;
    }
    if (taint_clear)
     {
       UINT32 regid; 
       assert (!REG_is_mm(reg) && !REG_is_xmm(reg));
       
       if (REG_is_gr(reg))
         regid = reg - REG_GR_BASE;
       else 
       {
         assert(REG_is_gr16(reg) || REG_is_gr8(reg));
         regid = reg - REG_AL + NR_REG(REG_GR);
       }
       
       IFCOND(ins);
       INS_InsertThenCall(ins,IPOINT_BEFORE,
         (AFUNPTR) RegisterUntaint,IARG_FAST_ANALYSIS_CALL,
         IARG_UINT32, iaddr,
         IARG_UINT32, regid,
         IARG_THREAD_ID,
         IARG_END);

       if (KnobDebug)
         TraceFile << "[TNT] " << "PC " << hex << iaddr << " untaint "
          << INS_Disassemble(ins) << endl;
    }
  }
  
  if (KnobDebug  && !taint_clear)
    TraceFile << "[TNT] " << "PC " << hex << iaddr << " did not untaint " 
      << INS_Disassemble(ins) << endl;
  
  return taint_clear;
}
//desc:处理不同指令的污点传播
//input：指令对象
//output:bool，是否处理完成，目前只有mov指令处理完成
bool Process_Specific(INS ins) {
  xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins); 
  return (*instrument_functions[opcode])(ins);
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
// Generic propagation logic based on Pin's interpretation of what is being read and written by an instruction
// For commonly invoked instructions, we create a fast path that is designed for each instruction specifically
// to reduce both analysis cost and instrumentation cost.
VOID InstructionProp(INS ins, VOID *v)
{
  REG reg;

  bool is_mem_read1, is_mem_read2, is_mem_write;
  ADDRINT iaddr = INS_Address(ins);
  UINT32 gr_read, gr_write, xt_read, xt_write,eflag_write;
  

  if (!crc32_Instrumentation_On) return;//OnDemand，只有按下了ALT+<，下面的程序才会执行

  

  //////////////////////////////////////////////////////////////////////////
  //******************************************
  //下面开始指令级别的污点传播  
  //******************************************
  
  if (Process_Specific(ins)) return; //调用相应类型指令的回调函数，先处理MOV指令的
 
  if (ConditinalJmp(ins))
  {

    INS_InsertCall(ins,IPOINT_BEFORE, 
      (AFUNPTR) CheckConditionalJMP,
      IARG_UINT32, iaddr,
      IARG_THREAD_ID,
      IARG_BRANCH_TAKEN,
      IARG_BRANCH_TARGET_ADDR,
      IARG_END);
    return;
  }
  //liu 1014
  
  //liu 1014



  // TODO:These are already instruction specific, need to move them to instfunction.c
  //查看是不是xor A,A 等类型，如果是，则清除污点
  if (INS_Mnemonic(ins) == "XOR" || INS_Mnemonic(ins) == "SUB" || INS_Mnemonic(ins) == "SBB")
    if (UntaintXorSub(ins))
      return; /* Untainting instructions do not propagate */
  
  xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins); 


  if (opcode == XED_ICLASS_SYSCALL 
    || opcode == XED_ICLASS_SYSENTER
    || opcode ==XED_ICLASS_CMPXCHG // note that we are skipping cmpxchg right now
    || INS_IsInterrupt(ins) )
  {
    return;
  }

  /* Step 1 - determine if we read or write any memory addresses */
    
  is_mem_read1 = INS_IsMemoryRead(ins);
  if (is_mem_read1)
    is_mem_read2 = INS_HasMemoryRead2(ins);
  else
    is_mem_read2 = false;

  is_mem_write = INS_IsMemoryWrite(ins);


  if (KnobDebug && !CompactLog)
    TraceFile << "[TNT] mem_r1 " << is_mem_read1 << " mem_r2 "
      << is_mem_read2 << " mem_w " << is_mem_write << " PC " << hex << iaddr <<endl;

  /* Step 2 - Create a list of all registers tracked by DIFT that are
   * read/written by the current instruction
   */
  //gr_read记录读的寄存器的编号，每一位表示一个寄存器编号，值1代表读了该寄存器，同理gr_write
  gr_read = gr_write = xt_read = xt_write = eflag_write=0;
  for (UINT32 i=0; i < INS_MaxNumRRegs(ins); i++)  //INS_MaxNumRRegs:Maximum number of read operands
  {
    reg =  INS_RegR(ins, i);

    if (!REG_is_dift(reg)) continue;

    if (KnobDebug && !CompactLog)
      TraceFile << " reg_r " << REG_StringShort(reg);

    if (REG_is_gr(reg))
      gr_read |= 1 << (reg - REG_GR_BASE);
    else if (REG_is_gr8(reg) || REG_is_gr16(reg))
    {
      gr_read |= 1 << (reg - REG_AL + NR_REG(REG_GR));
    }
     //add by richard 2012-11-1,considering the xmm register
  else if(REG_is_mm(reg))
  {
    xt_read |=1<<(reg-REG_MM_BASE);
  }
  else if (REG_is_xmm(reg))
  {
    xt_read |=1<< (reg-REG_MM_BASE+NR_REG(REG_MM));
  }

  }
  //找到所有写的寄存器,modified by richard :add writing eflags.
  for (UINT32 i=0; i < INS_MaxNumWRegs(ins); i++)
  {
    reg = INS_RegW(ins,i);

    if (!REG_is_dift(reg)&&reg!=REG_EFLAGS) continue;
           
    if (KnobDebug && !CompactLog) 
      TraceFile << " reg_w " << REG_StringShort(reg);
    if (REG_is_gr(reg))
      gr_write |= 1 << (reg - REG_GR_BASE);
    else if (REG_is_gr8(reg) || REG_is_gr16(reg))
    {
      gr_write |= 1 << (reg - REG_AL + NR_REG(REG_GR));
    }
  else if (reg==REG_EFLAGS)
  {
    eflag_write=1;
  }
  //add by richard 2012-11-1,considering the xmm register
  else if(REG_is_mm(reg))
  {
    xt_write |=1<<(reg-REG_MM_BASE);
  }
  else if (REG_is_xmm(reg))
  {
    xt_write |=1<< (reg-REG_MM_BASE+NR_REG(REG_MM));
  }
  }

 
  
  //对于rep前缀的指令，忽视对ecx,edi,esi的读写 
  if (INS_RepPrefix(ins)) 
  {
    gr_read &= ~(1 << (REG_ECX -REG_GR_BASE )); // ecx is used as counter in rep instructions
    gr_read &= ~(1 << (REG_EDI -REG_GR_BASE )); // edi is used as counter in rep instructions
    gr_read &= ~(1 << (REG_ESI -REG_GR_BASE )); // esi is used as counter in rep instructions

    gr_write &= ~(1 << (REG_ECX -REG_GR_BASE )); // ecx is used as counter in rep instructions
    gr_write &= ~(1 << (REG_EDI -REG_GR_BASE )); // edi is used as counter in rep instructions
    gr_write &= ~(1 << (REG_ESI -REG_GR_BASE )); // esi is used as counter in rep instructions

    
  if (KnobDebug && !CompactLog)
    TraceFile << " remove_addr_reg " << REG_StringShort(REG_ECX) << REG_StringShort(REG_EDI) << REG_StringShort(REG_ESI) << " from gr_read and gr_write " ;
  }
  if (KnobDebug && !CompactLog)
    TraceFile << endl;

  if (!gr_write && !xt_write&& !is_mem_write&&!eflag_write) 
    return; /* If we don't update any registers or memory 
             * then by definition no propagation will take place
             */

  /* Step 4 - Prepare arguments for call to DoProp
   * This assumes an instruction does not read/write to its own code,
   * i.e. does not write to the memory address indicated by the PC(EIP).
   */
  //////////////////////////////////////////////////////////////////////////
  //无内存读写，仅仅写了一个通用寄存器
  // no mem read or write, mmx read and write are false, no mem read or write, just write to one general register
  if (!MaxNumMaskReg(xt_read) && !MaxNumMaskReg(xt_write) && !is_mem_read1 &&
    !is_mem_write && MaxNumMaskReg(gr_write) == 1
    && gr_read < (1 << NR_REG(REG_GR)) 
    && gr_write < (1 << NR_REG(REG_GR)))
  {
    //无寄存器读，而又写了一个寄存器，那么这个被写的寄存器一定是干净的。
    if (MaxNumMaskReg(gr_read) == 0)
    {
      IFCOND(ins); //该线程是否开启了TaintPropagation
      INS_InsertThenCall(ins,IPOINT_BEFORE, 
        (AFUNPTR) RegisterUntaint,IARG_FAST_ANALYSIS_CALL,
        IARG_UINT32, iaddr,
        IARG_UINT32, MaskReg(gr_write,0),
        IARG_THREAD_ID,
        IARG_END);
    }
  //读了一个寄存器，写了一个寄存器，如果读得寄存器被污染了，写的寄存器也被污染了。
    else if (MaxNumMaskReg(gr_read) == 1)
    {
      assert (MaskReg(gr_read,0) < NR_REG(REG_GR));
      assert (MaskReg(gr_write,0) < NR_REG(REG_GR));
                    
      IFCOND(ins);   
      INS_InsertThenCall(ins,IPOINT_BEFORE, 
        (AFUNPTR) DoPropRegR1,IARG_FAST_ANALYSIS_CALL,
        IARG_UINT32, iaddr,
        IARG_UINT32, MaskReg(gr_read,0) + REG_GR_BASE,
        IARG_UINT32, MaskReg(gr_write,0) + REG_GR_BASE,
    IARG_UINT32,eflag_write,
        IARG_THREAD_ID,
        IARG_END);
      return;
    } 
  //读了两个寄存器，写了一个寄存器。读的两个寄存器中有一个被污染了，那么写的寄存器也被污染了。
    else if (MaxNumMaskReg(gr_read) == 2)
    {
      assert (MaskReg(gr_read,0) < NR_REG(REG_GR));
      assert (MaskReg(gr_write,0) < NR_REG(REG_GR));
      assert (MaskReg(gr_read,1) < NR_REG(REG_GR));
      IFCOND(ins);
      INS_InsertThenCall(ins,IPOINT_BEFORE, 
        (AFUNPTR) DoPropRegR2,IARG_FAST_ANALYSIS_CALL,
        IARG_UINT32, iaddr,
        IARG_UINT32, MaskReg(gr_read,0) + REG_GR_BASE,
        IARG_UINT32, MaskReg(gr_read,1) + REG_GR_BASE,
        IARG_UINT32, MaskReg(gr_write,0) + REG_GR_BASE,
        IARG_UINT32,eflag_write,
    IARG_THREAD_ID,
        IARG_END);
      return;
    }
  }
  //有内存读或内存写，但是没有额外的寄存器的读写，那么查看读集合是否被污染，如果是，则写集合一并被污染
  // there is mem read or write, but no xt reads or xt writes
  if (!MaxNumMaskReg(xt_read) && !MaxNumMaskReg(xt_write))
  {
    IFCOND(ins);
    INS_InsertThenCall(ins,IPOINT_BEFORE, 
      (AFUNPTR) DoPropNoExtReg,IARG_FAST_ANALYSIS_CALL,
      IARG_UINT32, iaddr,
      IARG_UINT32, gr_read, 
      IARG_UINT32, gr_write, 
      is_mem_read1 ? IARG_MEMORYREAD_EA : IARG_INST_PTR,
      is_mem_read2 ? IARG_MEMORYREAD2_EA : IARG_INST_PTR,
      is_mem_read1 ? IARG_MEMORYREAD_SIZE : IARG_INST_PTR,
      is_mem_write ? IARG_MEMORYWRITE_EA : IARG_INST_PTR,
      is_mem_write ? IARG_MEMORYWRITE_SIZE : IARG_INST_PTR,
      IARG_UINT32,eflag_write,
    IARG_THREAD_ID,
      IARG_END);
    return;
  }
  
  //having extra ins like xmm read and write
  IFCOND(ins);
  INS_InsertThenCall(ins,IPOINT_BEFORE, 
    (AFUNPTR) DoProp,
    IARG_FAST_ANALYSIS_CALL,
    IARG_UINT32, iaddr,
    IARG_UINT32, gr_read, IARG_UINT32, xt_read,
    IARG_UINT32, gr_write, IARG_UINT32, xt_write,
    is_mem_read1 ? IARG_MEMORYREAD_EA : IARG_INST_PTR,
    is_mem_read2 ? IARG_MEMORYREAD2_EA : IARG_INST_PTR,
    is_mem_read1 ? IARG_MEMORYREAD_SIZE : IARG_INST_PTR,
    is_mem_write ? IARG_MEMORYWRITE_EA : IARG_INST_PTR,
    is_mem_write ? IARG_MEMORYWRITE_SIZE : IARG_INST_PTR,
    IARG_THREAD_ID,
    IARG_END);
}
//liu func end 911

auto_ptr<string> GetNarrowOfWide(wchar_t *in) {
  /* Our output */
  //  string *out = new string;
  auto_ptr<string> out (new string);

  for (unsigned int i = 0; i < wcslen(in); i++) {
    out->push_back(
      use_facet<ctype<wchar_t> >(std::locale("")).narrow(in[i], '?')
		   );
  }

  return out;
}

/** Default Taint policy function */
bool defaultPolicy(uint32_t addr, uint32_t length, const char *msg) {
  static int intronum = -1;

  intronum++;

  cerr << "Taint introduction #" << intronum
       << ". @" << addr << "/" << length << " bytes: "
       << msg << endl;

  if (intronum >= g_skipTaints) {
    return true;
  } else {
    cerr << "Skipping taint introduction." << endl;
    return false;
  }
}

/**************** Initializers ****************/

//
TaintTracker::TaintTracker(ValSpecRec * env) 
  : taintnum(1),
    values(env),
    taint_net(false),
    taint_args(false),
    pf(defaultPolicy)
{
#ifdef _WIN32

  os_t WIN_VER = get_win_version();

  // cerr << "WIN_VER=" << WIN_VER << ", SEVEN=" << OS_SEVEN_SP0 << endl;

  for ( unsigned i = 0; i < num_syscalls; i++ ) {
    const char *name = syscalls[i].name;
    int from = get_syscall(name, WIN_VER);
    int to = get_syscall(name, OS_SEVEN_SP0);
    if (from != -1 && to != -1) {
      //cerr << "mapping " << name << ": " << from << " to " << to << endl; 
      syscall_map.insert( std::pair<unsigned int, unsigned int>( from, to ));
    }
  }
#endif
}

//
void TaintTracker::setCount(uint32_t cnt)
{
  count = cnt;
}

//
void TaintTracker::setTaintArgs(bool taint)
{
  taint_args = taint;
}

//
void TaintTracker::setTaintEnv(string env_var)
{
  taint_env.insert(env_var);
}

//
void TaintTracker::trackFile(string file)
{
  taint_files.insert(file);
  //char log[100];
  //strcpy(log,file.c_str());
  //mylog(log);
}

//
void TaintTracker::setTaintStdin()
{
#ifndef _WIN32
  fdInfo_t fd(string("stdin"), 0);
  fds[STDIN_FILENO] = fd;
#else
  assert(false);
#endif
}

//
void TaintTracker::setTaintNetwork()
{
  taint_net = true;
}

/**************** Helper Functions ****************/

//
bool TaintTracker::isValid(RegMem_t type)
{
  return (type.type != NONE);
}

// 
bool TaintTracker::isReg(RegMem_t type)
{
    return (type.type == REGISTER);
}

bool TaintTracker::isMem(RegMem_t type)
{
    return (type.type == MEM);
}

//1208////////////////////////////////////////////
void TaintTracker::trackOffset(uint32_t offset, uint32_t length)
{
  taint_s  t(offset,length);
  taint_sources.insert(t);
}
// 
uint32_t TaintTracker::exists(context &ctx, uint32_t elem)
{
  return (ctx.find(elem) != ctx.end());
}


uint32_t TaintTracker::getSize(RegMem_t type) {
    return type.size / 8;
}


// Combining two taint tags
uint32_t TaintTracker::combineTaint(uint32_t oldtag, uint32_t newtag)
{
  if (newtag) {// its tainted
    if (oldtag == NOTAINT)
      return newtag; // FIXME
    else 
      return MIXED_TAINT;
  }
  return oldtag;
}

// 
void TaintTracker::printRegs(context &delta)
{
  cerr << hex << endl << " ----------- Tainted Regs ------------ " << endl;
  for (context::iterator it = delta.begin(), ie = delta.end() ; it != ie ; ++it)
       cerr << REG_StringShort((REG)it->first) << " = " << it->second << endl;
}

//
void TaintTracker::printMem()
{
  cerr << hex << endl << " ----------- Tainted Mem ------------ " << endl;
  for (context::iterator it = memory.begin(), ie = memory.end() ; it != ie ; ++it)
    cerr << "Addr: " << it->first << " -> " << it->second << endl;
}

/***************** Taint Handlers *******************/

// Reads length bytes from source at offset, putting the bytes at
// addr. If offset is -1, new tainted bytes are assigned. Otherwise,
// the (source,offset) tuple are compared for each byte to see if that
// resource has been used before, and if so, the same taint number is given.
FrameOption_t TaintTracker::introMemTaint(uint32_t addr, uint32_t length, const char *source, int64_t offset) {

  FrameOption_t fb;
  THREADID idd= PIN_ThreadId();
  TAINT_Analysis_On=true;
  //liu 911
  for(ADDRINT i=0;i<length;i++)
    {
      set<int> t;
      t.clear();
      t.insert(offset+i);
      SetMemTaintSource(addr+i,1,t,0,idd);
    }

    Setmem_taint(addr,length, true, 0,idd);
    TAINT_Instrumentation_On = true;
    cerr<<"again!!!!!!!!!!!!!!!!!!!"<<endl;
    cerr<<length<<" "<<offset<<endl;
    dump_taint_src();

  if ((*pf)(addr, length, source) && length > 0) {

    for (unsigned int i = 0; i < length; i++) {
      uint32_t t = 0;
      if (offset == -1 || reuse_taintids == false) {
        t = taintnum++;
      } else {
        // Check if (source, offset+i) has a byte. If not, assign one.
        resource_t r(source, offset+i);
        if (taint_mappings.find(r) != taint_mappings.end()) {
          t = taint_mappings[r];
          //cerr << "found mapping from " << source << " to " << offset+i << " on taint num " << t << endl;
        } else {
          t = taintnum++;
          taint_mappings[r] = t;
		  //1208////////////////////////////////////////////////
          g_TaintAsistBuff[ g_tsbufidx + 1] = offset+i;
		  g_tsbufidx++;
		  *(uint32_t *)g_TaintAsistBuff = g_tsbufidx;
		  ////////////////////////
          //cerr << "adding new mapping from " << source << " to " << offset+i << " on taint num " << t << endl;
        }
      }
      /* Mark memory as tainted */
      setTaint(memory, addr+i, t);
      taint_intro* tfi = fb.f.mutable_taint_intro_frame()->mutable_taint_intro_list()->add_elem();
      tfi->set_taint_id(t);
      tfi->set_addr(addr+i);
      uint8_t value;
      assert (PIN_SafeCopy((void*) &value, (void*) (addr+i), 1) == 1);
      tfi->set_value((void*) &value, 1);
    }
    fb.b = true;
    return fb;
  } else {
    fb.b = false;
    return fb;
  }
}

// Reads length bytes from source at offset, putting the bytes at
// addr. Also adds length to the offset of the resource.
FrameOption_t TaintTracker::introMemTaintFromFd(uint32_t fd, uint32_t addr, uint32_t length) {
  assert(fds.find(fd) != fds.end());
  //1208/////////////////////////////////////////////////////////
  //////////////////////////////////////////
  std::set<taint_s>::iterator pos;
  FrameOption_t tfs;
  for (pos = taint_sources.begin(); pos != taint_sources.end();pos++) 
  {
  	///first is file offset ,second is length
  	int lower = pos->first > fds[fd].offset ? pos->first:fds[fd].offset;
  	int upper = pos->first + pos->second < fds[fd].offset +length? pos->first + pos->second:fds[fd].offset +length;
  	if(upper >=lower)
  	{
      //char log[]="taint intro\n";
      //mylog(log);
  		
  		
  		tfs = introMemTaint(addr+ lower - fds[fd].offset, upper - lower,
  			fds[fd].name.c_str(), lower);
  		  
  	}
  }



  /////////////////////////////////////////////
  //FrameOption_t tfs = introMemTaint(addr, length, fds[fd].name.c_str(), fds[fd].offset);
  fds[fd].offset += length;
  return tfs;
}

//
void TaintTracker::setTaint(context &ctx, uint32_t key, uint32_t tag)
{
  if (tag == NOTAINT)
    ctx.erase(key);
  else ctx[key] = tag;
}


// 
uint32_t TaintTracker::getTaint(context &ctx, uint32_t elem)
{
  if (exists(ctx, elem))
    return ctx[elem];
  return NOTAINT;
}

// 
uint32_t TaintTracker::getMemTaint(uint32_t addr, RegMem_t type)
{
  uint32_t tag = NOTAINT;
  //cerr << "Getting memory " << addr << endl;
  uint32_t size = getSize(type);
  for (uint32_t i = 0 ; i < size ; i++) {
    uint32_t status = getTaint(memory, addr+i);
    tag = combineTaint(tag, status);
  }
  return tag;
}

void TaintTracker::untaintMem(uint32_t addr) {
  setTaint(memory, addr, NOTAINT);
}

// 
uint32_t TaintTracker::getRegTaint(context &delta, uint32_t reg)
{
  // cout << "Partial register: " << REG_StringShort((REG)reg) << endl;
  REG temp = REG_FullRegName((REG)reg);
  // cerr << "Full register: " << REG_StringShort(temp) << endl;
  return getTaint(delta,temp);
}

// 
uint32_t TaintTracker::getReadTaint(context &delta)
{
  uint32_t tag = NOTAINT, tmp_tag = NOTAINT;
  for (uint32_t i = 0 ; i < count ; i++) {
    if ((values[i].usage & RD) == RD) {
      // this is a read
        if (isReg(values[i].type) 
            && (values[i].loc != REG_EFLAGS)) // FIXME: no control-flow taint
            tmp_tag = getRegTaint(delta, values[i].loc);
        else if (isMem(values[i].type))
            tmp_tag = getMemTaint(values[i].loc, values[i].type);
        tag = combineTaint(tag, tmp_tag);
    }
  }
  return tag;
}

/************* External Taint Hooks **************/

/** Called after a system call to untaint the output register */
void TaintTracker::postSysCall(context &delta) {

  /* Windows uses EDX, and Linux uses EAX */

  #ifdef _WIN32
    setTaint(delta, SCOUTREG_WIN, NOTAINT);
  #else /* linux */
    setTaint(delta, SCOUTREG_LIN, NOTAINT);
  #endif
}

void TaintTracker::acceptHelper(uint32_t fd) {
  if (taint_net) {
    cerr << "Tainting fd " << fd << endl;
    fdInfo_t fdinfo(string("accept"), 0);
    fds[fd] = fdinfo;
  }
}
void TaintTracker::OpenHelper(uint32_t fd,char * s) {
  
    string cppfilename(s);
    if (cppfilename.find("doc") != string::npos) {
      cerr << s <<endl;
    }
    
    for (std::set<string>::iterator i = taint_files.begin();i != taint_files.end();i++) 
    {
      if (cppfilename.find(*i) != string::npos) {
        state = __NR_open;
        cerr << s <<endl;
        cerr << "Tainting fd " << fd << endl;
        fdInfo_t fdinfo(string("file ") + string(s), 0);
        fds[fd] = fdinfo;
      }
    }
  
}

FrameOption_t TaintTracker::recvHelper(uint32_t fd, void *ptr, size_t len) {
  uint32_t addr = reinterpret_cast<uint32_t> (ptr);

  if (fds.find(fd) != fds.end()) {
    cerr << "Tainting " << len << " bytes of recv @" << addr << endl;
    return introMemTaintFromFd(fd, addr, len);
  } else {
    return FrameOption_t(false);
  }
}

/******************* Taint Analysis Rules ***************/

/******** Taint Introduction **********/

//
#ifdef _WIN32
std::vector<frame> TaintTracker::taintArgs(char *cmdA, wchar_t *cmdW)
{
  std::vector<frame> frms;
  FrameOption_t fo;
  std::vector<frame> tfrms;
  if (taint_args) {
    size_t lenA = strlen(cmdA);
    size_t lenW = wcslen(cmdW);
    size_t bytesA = lenA*sizeof(char);
    size_t bytesW = lenW*sizeof(wchar_t);
    cerr << "Tainting multibyte command-line arguments: " << bytesA << " bytes @ " << (unsigned int)(cmdA) << endl;
    
    /* Taint multibyte command line */
    fo = introMemTaint((uint32_t)cmdA, bytesA, "Tainted Arguments", -1);
    if (fo.b) { frms.push_back(fo.f); }
    cerr << "Tainting wide command-line arguments: " << bytesW << " bytes @ " << (unsigned int)(cmdW) << endl;
    fo = introMemTaint((uint32_t)cmdW, bytesW, "Tainted Arguments", -1);
    if (fo.b) { frms.push_back(fo.f); }
  }
  return frms;
}
#else
std::vector<frame> TaintTracker::taintArgs(int argc, char **argv)
{

  std::vector<frame> fv;

  if (taint_args) {
    cerr << "Tainting command-line arguments" << endl;
    for ( int i = 1 ; i < argc ; i++ ) {
      cerr << "Tainting " << argv[i] << endl;
      size_t len = strlen(argv[i]);
      FrameOption_t fo = introMemTaint((uint32_t)argv[i], len, "Arguments", -1);
      if (fo.b) { fv.push_back(fo.f); }
    }
  }

  return fv;
}
#endif

//
#ifdef _WIN32
std::vector<frame> TaintTracker::taintEnv(char *env, wchar_t *wenv)
{
  /* See MSDN docs here: http://msdn.microsoft.com/en-us/library/ms683187(VS.85).aspx 
   * Basically, env is a pointer to
   * var=val\x00
   * var2=val2\x00
   * ...
   * \x00\x00
   */
  std::vector<frame> fv;
  //  std::vector<frame> frms;

  // /* Multibyte strings */
  // for ( ; *env != '\x00'; env += (strlen(env) + 1 /* null */)) {
  //   string var(env);
  //   int equal = var.find('=');
  //   var = var.substr(0, equal);
  //   if (taint_env.find(var) != taint_env.end()) {
  //     uint32_t len = strlen(env) - var.size();
  //     uint32_t addr = (uint32_t)env+equal+1;
  //     cerr << "Tainting environment variable: " << var << " @" << (int)addr << " " << len << " bytes" << endl;
  //     for (uint32_t j = 0 ; j < len ; j++) {
  // 	setTaint(memory, (addr+j), taintnum++);
  //     }
  //     TaintFrame frm;
  //     frm.id = ENV_ID;
  //     frm.addr = addr;
  //     frm.length = len;
  //     frms.push_back(frm);
  //   }
  // }

  /* Wide strings */
  if (wenv) {
    for ( ; *wenv != '\x00'; wenv += (wcslen(wenv) + 1 /* null */)) {
      string ns = *GetNarrowOfWide(wenv);
      wstring wvar(wenv);
      string var(ns);
      int equal = var.find('=');
      var = var.substr(0, equal);
      
      if (taint_env.find(var) != taint_env.end()) {
        uint32_t numChars = wcslen(wenv) - var.size();
	uint32_t numBytes = numChars * sizeof(wchar_t);
        uint32_t addr = (uint32_t) (wenv+equal+1);
        cerr << "Tainting environment variable: " << var << " @" << (int)addr << " " << numChars << " bytes" << endl;
	FrameOption_t fo = introMemTaint(addr, numBytes, "Environment Variable", -1);
	if (fo.b) { fv.push_back(fo.f); }
      }
    }
  }

  return fv;
}
#else /* unix */
std::vector<frame> TaintTracker::taintEnv(char **env)
{

  std::vector<frame> fv;

  for ( int i = 1 ; env[i] ; i++ ) {
    string var(env[i]);
    int equal = var.find('=');
    var = var.substr(0,equal);
    if (taint_env.find(var) != taint_env.end()) {
      uint32_t len = strlen(env[i]) - var.size();
      uint32_t addr = (uint32_t)env[i]+equal+1;
      cerr << "Tainting environment variable: " << var << " @" << (int)addr << endl;
      FrameOption_t fo = introMemTaint(addr, len, "environment variable", -1);
      if (fo.b) { fv.push_back(fo.f); }
    }
  }
  return std::vector<frame> ();
}
#endif

/** This function is called right before a system call. */
bool TaintTracker::taintPreSC(uint32_t callno, const uint64_t *args, /* out */ uint32_t &state)
{
  state = __NR_nosyscall;
  bool reading_tainted = false;
  char filename[128];
  switch (callno) {
      case __NR_open:
      {
          strncpy(filename, (char *)args[0],128); 
          //cerr<<filename<<endl;
  	       // Search for each tainted filename in filename
        	string cppfilename(filename);
          //cerr<<filename<<endl;
          //mylog(filename);
          //char log[100];
          //sprintf(log,"before open fd=%s pid=%x tid=%x\n ",(char*)args[0],PIN_GetPid(),PIN_GetTid());
          //mylog(log);
        	for (std::set<string>::iterator i = taint_files.begin();
        	     i != taint_files.end();
        	     i++) {
        	     if (cppfilename.find(*i) != string::npos) {
        	       state = __NR_open;
                  //char log[100];
                  //sprintf(log,"before open fd=%s pid=%x tid=%x\n ",(char*)args[0],PIN_GetPid(),PIN_GetTid());
                  //cerr << log << endl;
                  //mylog(log);
        	     }
        	}
          
        	if (state == __NR_open) {
        	  cerr << "Opening tainted file: " << cppfilename << endl;
        	} else {
        	  //cerr << "Not opening " << cppfilename << endl;
        	}
      }
              break;
      case __NR_close:
        state = __NR_close;
        break;
        // TODO: do we care about the offset?
      case __NR_mmap:
      case __NR_mmap2:
      
        if (fds.find(args[4]) != fds.end()) {
          cerr << "mmapping " << args[0] << endl;
          state = __NR_mmap2;
        }
        break;
      case __NR_read: 
        //char log[100];
        //sprintf(log,"before read fd=%lld  pid=%x tid=%x\n ",args[0],PIN_GetPid(),PIN_GetTid());
        //mylog(log);
        //cerr<<log<<endl;
        //cerr<<"before read "<<fds[args[0]].name <<endl;
        
        //cerr << log << endl;
        
        //if (fds.find(args[0]) != fds.end()) {

        //if(args[0]==taintfd)
        //char taint_fd_file[20];
        //int suc ;
        //int intaintfd;
        //suc = read_file(taint_fd_file,"taint_file.txt");
        //intaintfd = atoi(taint_fd_file);

        //if((args[0] == intaintfd)&& (suc==1))
        if (fds.find(args[0]) != fds.end()) 
        {
          state = __NR_read;
          cerr << "find fd " << fds[args[0]].name <<  endl;
          //cerr <<"before read "<<endl;
          reading_tainted = true;
        }
        else
        {
          //cerr << args[0] << " not found" << endl;
        }
        break;
      case __NR_socketcall:
        // TODO: do we need to distinguish between sockets?
        if (taint_net) {
          state = __NR_socketcall;
          if (args[0] == _A1_recv)
            reading_tainted = true;
        }
        break;
      case __NR_execve:
        break;
      case __NR_lseek:
        if (fds.find(args[0]) != fds.end()) {
          state = __NR_lseek;
        }
        break;
        

    
  default:
    //    LOG(string("Unknown system call") + *(get_name(callno)) + string("\n"));
    //    cerr << "Unknown system call " << callno << " " << *(get_name(callno)) << endl;
    break;
  }
  return reading_tainted;
}

 /** This function is called immediately following a system call. */
FrameOption_t TaintTracker::taintPostSC(const uint32_t bytes, 
                                     const uint64_t *args,
                                     uint32_t &addr,
                                     uint32_t &length,
				     const uint32_t state)
{
  //for ( int i = 0 ; i < MAX_SYSCALL_ARGS ; i ++ )
  //cout << hex << " " << args[i] ;
  //cout << endl ;
  //cerr<<"taintPostSC"<<endl;
  uint32_t fd = -1;
  
  switch (state) {

    case __NR_socketcall:
      switch (args[0]) {
        case _A1_recv:
              addr = ((uint32_t *)args[1])[1];
              fd = ((uint32_t*) args[1])[0];
              length = bytes;
              cerr << "Tainting " 
                   << bytes 
                   << " bytes from socket " << fd << endl;
              return introMemTaintFromFd(fd, addr, length);
              //return true;
      
        case _A1_accept:
              if (bytes != (uint32_t)UNIX_FAILURE) {
                cerr << "Accepting an incoming connection" << endl;
                fdInfo_t fdinfo(string("accept"), 0);
                fds[bytes] = fdinfo;
              }
              break;
        case _A1_socket:
              if (bytes != (uint32_t)UNIX_FAILURE) {
                cerr << "Opening a tainted socket " << bytes << endl;
                fdInfo_t fdinfo(string("socket"), 0);
                fds[bytes] = fdinfo;
              }
              break;
        default:
              break;
        }
        break;
  case __NR_open:
        // "bytes" contains the file descriptor
        if (bytes != (uint32_t)(UNIX_FAILURE)) { /* -1 == error */
          /* args[0] is filename */
          char *filename = reinterpret_cast< char *> (args[0]);
          fdInfo_t fdinfo(string("file ") + string(filename), 0);
          fds[bytes] = fdinfo;
          //cerr<<"open taint file "<<filename<<endl;
          //char taint_fd_file[10];
          //sprintf(taint_fd_file,"%d ",bytes);
          //write_file(taint_fd_file,"taint_file.txt");
          
          //taintfd = bytes;
          
          //char log[100];
          //sprintf(log,"after open fd=%d %s pid=%x tid=%x\n ",bytes,openfilename,PIN_GetPid(),PIN_GetTid());
          //mylog(log);
          //cerr << log << endl;
          
          
          
        }
        break;
  case __NR_close:
        if (bytes == (uint32_t)(UNIX_SUCCESS) && fds.find(args[0]) != fds.end()) {
          cerr << "closed tainted fd " << args[0] << endl;
          fds.erase(args[0]);
        }
        break;
  case __NR_mmap:
  case __NR_mmap2:
      
      
        addr = bytes;
        fd = args[4];
        length = args[1];
        //uint32_t offset = args[6];
        if ((int)addr != -1) {
          off_t offset;
          assert (PIN_SafeCopy(&offset, (void*) args[5], sizeof(off_t)) == sizeof(off_t));
          cout << "Tainting " 
               << length 
               << " bytes from mmap of fd "
               << fd
               << " at offset "
               << offset
               << endl;
          //return introMemTaint(addr, length, fds[fd].name.c_str(), (int64_t)offset);
        }
        break;
      

  case __NR_read:
      {
        fd = args[0];
        addr = args[1];
        length = bytes;
        if ((int)length != -1) {

          cout << "Tainting " 
               << length 
               << " bytes from read at " << addr << ", fd=" << args[0]
               << endl;
          
          //return introMemTaintFromFd(fd, addr, length);
        }
        break;
      }
  case __NR_lseek:
        if (bytes != UNIX_FAILURE) {
          cerr << "Changing offset for fd " << args[0] << " to " << bytes << endl;
          fds[args[0]].offset = bytes;
        } else {
          cerr << "lseek() failure!" << endl;
        }
        break;


      default:
        break;
  }
  return FrameOption_t(false);
}

/******** Taint Propagation **********/

// Set taint of the current values based on taint context information
void TaintTracker::setTaintContext(context &delta)
{
  uint32_t tag;
  for (uint32_t i = 0 ; i < count ; i++) {
      if (isReg(values[i].type)) {
          if ((tag = getRegTaint(delta, values[i].loc)) != NOTAINT) {
	// cerr << "register: " << REG_StringShort((REG)values[i].loc) << " is tainted" << endl;
              values[i].taint = tag;
          }
      } else if (isValid(values[i].type)) {
          if ((tag = getTaint(memory,values[i].loc)) != NOTAINT) {
              //cerr << "memory: " << values[i].loc << " is tainted" << endl;
              values[i].taint = tag;
          }
      }
  }
  
}

// Reset the taint status of registers and memory
void TaintTracker::resetTaint(context &delta) {
  delta.clear();
  memory.clear();
}

// Add taint 'tag' to all written operands
void TaintTracker::addTaintToWritten(context &delta, uint32_t tag)
{
  uint32_t loc;
  cerr <<hex ;
  for (uint32_t i = 0 ; i < count ; i++) {
    if ((values[i].usage & WR) == WR)  {
      if (isReg(values[i].type)) {
	loc = REG_FullRegName((REG)values[i].loc);
	setTaint(delta,loc,tag);
	values[i].taint = getRegTaint(delta, loc);
	//cerr << "new " << REG_StringShort((REG)values[i].loc) 
	//     << " taint: " << values[i].taint << endl;
      } else if (isMem(values[i].type)) {
	//cerr << hex << "writing " << values[i].loc << " = " << tag << endl;
	loc = values[i].loc;
	uint32_t size = getSize(values[i].type);
	for(uint32_t j = 0 ; j < size ; j++) {
	  //cerr << " Tainting memory " << loc + j << endl;
	  setTaint(memory,loc+j,tag);
	}
	values[i].taint = getTaint(memory,loc);
	//cerr << "mem taint: " << values[i].taint << endl;
      } 
    }
  }
}

// Propagate taint information to written operands
void TaintTracker::taintPropagation(context &delta)
{
  //printMem();
  //printRegs();
  uint32_t taint_tag = getReadTaint(delta);
  addTaintToWritten(delta, taint_tag);
}

/******** Taint Checking **********/

// Check if the current instruction has tainted operands
bool TaintTracker::hasTaint(context &delta)
{
  cerr << hex ;
  for (uint32_t i = 0 ; i < count ; i++) {
    if (isReg(values[i].type)) {
      if (getRegTaint(delta, values[i].loc) != NOTAINT) {
	//cerr << "Tainted: " << REG_StringShort((REG)values[i].loc) << endl;
	return true;
      }
    } else if (isValid(values[i].type)) {
      if (getTaint(memory,values[i].loc) != NOTAINT) {
	//cerr << "Tainted Memory: " << values[i].loc << endl;
	return true;
      }
    }
  }
  return false;
}

// 
// bool TaintTracker::propagatedTaint(bool branch)
// {
//   if (branch)
//     return false;
//   for (uint32_t i = 0 ; i < count ; i++)
//     if ((values[i].usage == RD)
//         && isReg(values[i].type)
//         && values[i].loc != REG_EFLAGS
//         && values[i].taint != NOTAINT)
//       return true;
//   return false;
// } 

// Check of EIP is tainted
bool TaintTracker::taintChecking()
{
  for (uint32_t i = 0 ; i < count ; i++)
    if ((values[i].loc == REG_INST_PTR)
        && (isReg(values[i].type))
        && (values[i].taint != NOTAINT)) {
      return false;
    }
  return true;
}
