/* File generated from arch.idl */

#include <stddef.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>
#ifdef Custom_tag
#include <caml/custom.h>
#include <caml/bigarray.h>
#endif
#include <caml/camlidlruntime.h>


#include "arch.h"

int camlidl_transl_table_arch_enum_1[78] = {
  bfd_arch_unknown,
  bfd_arch_obscure,
  bfd_arch_m68k,
  bfd_arch_vax,
  bfd_arch_i960,
  bfd_arch_or32,
  bfd_arch_sparc,
  bfd_arch_spu,
  bfd_arch_mips,
  bfd_arch_i386,
  bfd_arch_l1om,
  bfd_arch_we32k,
  bfd_arch_tahoe,
  bfd_arch_i860,
  bfd_arch_i370,
  bfd_arch_romp,
  bfd_arch_convex,
  bfd_arch_m88k,
  bfd_arch_m98k,
  bfd_arch_pyramid,
  bfd_arch_h8300,
  bfd_arch_pdp11,
  bfd_arch_plugin,
  bfd_arch_powerpc,
  bfd_arch_rs6000,
  bfd_arch_hppa,
  bfd_arch_d10v,
  bfd_arch_d30v,
  bfd_arch_dlx,
  bfd_arch_m68hc11,
  bfd_arch_m68hc12,
  bfd_arch_z8k,
  bfd_arch_h8500,
  bfd_arch_sh,
  bfd_arch_alpha,
  bfd_arch_arm,
  bfd_arch_ns32k,
  bfd_arch_w65,
  bfd_arch_tic30,
  bfd_arch_tic4x,
  bfd_arch_tic54x,
  bfd_arch_tic6x,
  bfd_arch_tic80,
  bfd_arch_v850,
  bfd_arch_arc,
  bfd_arch_m32c,
  bfd_arch_m32r,
  bfd_arch_mn10200,
  bfd_arch_mn10300,
  bfd_arch_fr30,
  bfd_arch_frv,
  bfd_arch_moxie,
  bfd_arch_mcore,
  bfd_arch_mep,
  bfd_arch_ia64,
  bfd_arch_ip2k,
  bfd_arch_iq2000,
  bfd_arch_mt,
  bfd_arch_pj,
  bfd_arch_avr,
  bfd_arch_bfin,
  bfd_arch_cr16,
  bfd_arch_cr16c,
  bfd_arch_crx,
  bfd_arch_cris,
  bfd_arch_rx,
  bfd_arch_s390,
  bfd_arch_score,
  bfd_arch_openrisc,
  bfd_arch_mmix,
  bfd_arch_xstormy16,
  bfd_arch_msp430,
  bfd_arch_xc16x,
  bfd_arch_xtensa,
  bfd_arch_z80,
  bfd_arch_lm32,
  bfd_arch_microblaze,
  bfd_arch_last,
};

int camlidl_ml2c_arch_enum_bfd_architecture(value _v1)
{
  int _c2;
  _c2 = camlidl_transl_table_arch_enum_1[Int_val(_v1)];
  return _c2;
}

value camlidl_c2ml_arch_enum_bfd_architecture(int _c1)
{
  value _v2;
  _v2 = camlidl_find_enum(_c1, camlidl_transl_table_arch_enum_1, 78, "enum bfd_architecture: bad enum bfd_architecture value");
  return _v2;
}

