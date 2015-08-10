/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include "enc_base.h"
#include "enc_wrapper.h"
#include "dec_base.h"
#include "utils/Log.h"

//#define PRINT_ENCODER_STREAM
bool dump_x86_inst = false;

/**
 * @brief Provides mapping between PhysicalReg and RegName used by encoder
 * @param physicalReg The physical register
 * @return Returns encoder's register name
 */
static RegName mapFromPhysicalReg (int physicalReg)
{
    RegName reg = RegName_Null;

    //Get mapping between PhysicalReg and RegName
    switch (physicalReg)
    {
        case PhysicalReg_EAX:
            reg = RegName_EAX;
            break;
        case PhysicalReg_EBX:
            reg = RegName_EBX;
            break;
        case PhysicalReg_ECX:
            reg = RegName_ECX;
            break;
        case PhysicalReg_EDX:
            reg = RegName_EDX;
            break;
        case PhysicalReg_EDI:
            reg = RegName_EDI;
            break;
        case PhysicalReg_ESI:
            reg = RegName_ESI;
            break;
        case PhysicalReg_ESP:
            reg = RegName_ESP;
            break;
        case PhysicalReg_EBP:
            reg = RegName_EBP;
            break;
        case PhysicalReg_XMM0:
            reg = RegName_XMM0;
            break;
        case PhysicalReg_XMM1:
            reg = RegName_XMM1;
            break;
        case PhysicalReg_XMM2:
            reg = RegName_XMM2;
            break;
        case PhysicalReg_XMM3:
            reg = RegName_XMM3;
            break;
        case PhysicalReg_XMM4:
            reg = RegName_XMM4;
            break;
        case PhysicalReg_XMM5:
            reg = RegName_XMM5;
            break;
        case PhysicalReg_XMM6:
            reg = RegName_XMM6;
            break;
        case PhysicalReg_XMM7:
            reg = RegName_XMM7;
            break;
        default:
            //We have no mapping
            reg = RegName_Null;
            break;
    }

    return reg;
}

//getRegSize, getAliasReg:
//OpndSize, RegName, OpndExt: enum enc_defs.h
inline void add_r(EncoderBase::Operands & args, int physicalReg, OpndSize sz, OpndExt ext = OpndExt_None) {
    if (sz == OpndSize_128)
    {
        //For xmm registers, the encoder table contains them as 64-bit operands. Since semantics are determined
        //by the encoding of the mnemonic, we change the size to 64-bit to make encoder happy. It will still
        //generate the code for 128-bit size since for 64-bit all instructions have different encoding to use mmx.
        sz = OpndSize_64;
    }

    RegName reg = mapFromPhysicalReg (physicalReg);
    if (sz != getRegSize(reg)) {
       reg = getAliasReg(reg, sz);
    }
    args.add(EncoderBase::Operand(reg, ext));
}
inline void add_m(EncoderBase::Operands & args, int baseReg, int disp, OpndSize sz, OpndExt ext = OpndExt_None) {
    if (sz == OpndSize_128)
    {
        //For xmm registers, the encoder table contains them as 64-bit operands. Since semantics are determined
        //by the encoding of the mnemonic, we change the size to 64-bit to make encoder happy. It will still
        //generate the code for 128-bit size since for 64-bit all instructions have different encoding to use mmx.
        sz = OpndSize_64;
    }

    args.add(EncoderBase::Operand(sz,
                                  mapFromPhysicalReg (baseReg),
                                  RegName_Null, 0,
                                  disp, ext));
}
inline void add_m_scale(EncoderBase::Operands & args, int baseReg, int indexReg, int scale,
                        OpndSize sz, OpndExt ext = OpndExt_None) {
    if (sz == OpndSize_128)
    {
        //For xmm registers, the encoder table contains them as 64-bit operands. Since semantics are determined
        //by the encoding of the mnemonic, we change the size to 64-bit to make encoder happy. It will still
        //generate the code for 128-bit size since for 64-bit all instructions have different encoding to use mmx.
        sz = OpndSize_64;
    }

    args.add(EncoderBase::Operand(sz,
                                  mapFromPhysicalReg (baseReg),
                                  mapFromPhysicalReg (indexReg), scale,
                                  0, ext));
}
inline void add_m_disp_scale(EncoderBase::Operands & args, int baseReg, int disp, int indexReg, int scale,
                        OpndSize sz, OpndExt ext = OpndExt_None) {
    if (sz == OpndSize_128)
    {
        //For xmm registers, the encoder table contains them as 64-bit operands. Since semantics are determined
        //by the encoding of the mnemonic, we change the size to 64-bit to make encoder happy. It will still
        //generate the code for 128-bit size since for 64-bit all instructions have different encoding to use mmx.
        sz = OpndSize_64;
    }

    args.add(EncoderBase::Operand(sz,
                                  mapFromPhysicalReg (baseReg),
                                  mapFromPhysicalReg (indexReg), scale,
                                  disp, ext));
}

inline void add_fp(EncoderBase::Operands & args, unsigned i, bool dbl) {
    return args.add((RegName)( (dbl ? RegName_FP0D : RegName_FP0S) + i));
}
inline void add_imm(EncoderBase::Operands & args, OpndSize sz, int value, bool is_signed) {
    //assert(n_size != imm.get_size());
    args.add(EncoderBase::Operand(sz, value,
             is_signed ? OpndExt_Signed : OpndExt_Zero));
}

#define MAX_DECODED_STRING_LEN 1024
char tmpBuffer[MAX_DECODED_STRING_LEN];

void printOperand(const EncoderBase::Operand & opnd) {
    unsigned int sz;
    if(!dump_x86_inst) return;
    sz = strlen(tmpBuffer);
    if(opnd.size() != OpndSize_32) {
        const char * opndSizeString = getOpndSizeString(opnd.size());

        if (opndSizeString == NULL) {
            // If the string that represents operand size is null it means that
            // the operand size is an invalid value. Although this could be a
            // problem if instruction is corrupted, technically failing to
            // disassemble is not fatal. Thus, let's warn but proceed with using
            // an empty string.
            ALOGW("JIT-WARNING: Cannot decode instruction operand size.");
            opndSizeString = "";
        }

        sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN - sz, "%s ",
                opndSizeString);
    }
    if(opnd.is_mem()) {
        if(opnd.scale() != 0) {
            sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz,
                           "%d(%s,%s,%d)", opnd.disp(),
                           getRegNameString(opnd.base()),
                           getRegNameString(opnd.index()), opnd.scale());
        } else {
            sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, "%d(%s)",
                           opnd.disp(), getRegNameString(opnd.base()));
        }
    }
    if(opnd.is_imm()) {
        sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, "#%x",
                       (int)opnd.imm());
    }
    if(opnd.is_reg()) {
        sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, "%s",
                       getRegNameString(opnd.reg()));
    }
}
//TODO: the order of operands
//to make the printout have the same order as assembly in .S
//I reverse the order here
void printDecoderInst(Inst & decInst) {
    unsigned int sz;
    if(!dump_x86_inst) return;
    sz = strlen(tmpBuffer);
    sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, "%s ",
                   EncoderBase::toStr(decInst.mn));
    for(unsigned int k = 0; k < decInst.argc; k++) {
        if(k > 0) {
            sz = strlen(tmpBuffer);
            sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, ", ");
        }
        printOperand(decInst.operands[decInst.argc-1-k]);
    }
    ALOGE("%s", tmpBuffer);
}
void printOperands(EncoderBase::Operands& opnds) {
    unsigned int sz;
    if(!dump_x86_inst) return;
    for(unsigned int k = 0; k < opnds.count(); k++) {
        if(k > 0) {
            sz = strlen(tmpBuffer);
            sz += snprintf(&tmpBuffer[sz], MAX_DECODED_STRING_LEN-sz, ", ");
        }
        printOperand(opnds[opnds.count()-1-k]);
    }
}
void printEncoderInst(Mnemonic m, EncoderBase::Operands& opnds) {
    if(!dump_x86_inst) return;
    snprintf(tmpBuffer, MAX_DECODED_STRING_LEN, "--- ENC %s ",
             EncoderBase::toStr(m));
    printOperands(opnds);
    ALOGE("%s", tmpBuffer);
}
int decodeThenPrint(char* stream_start) {
    if(!dump_x86_inst) return 0;
    snprintf(tmpBuffer, MAX_DECODED_STRING_LEN, "--- INST @ %p: ",
             stream_start);
    Inst decInst;
    unsigned numBytes = DecoderBase::decode(stream_start, &decInst);
    printDecoderInst(decInst);
    return numBytes;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm(Mnemonic m, OpndSize size, int imm, char * stream) {
    EncoderBase::Operands args;
    //assert(imm.get_size() == size_32);
    add_imm(args, size, imm, true/*is_signed*/);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT unsigned encoder_get_inst_size(char * stream) {
    Inst decInst;
    unsigned numBytes = DecoderBase::decode(stream, &decInst);
    return numBytes;
}

extern "C" ENCODER_DECLARE_EXPORT uintptr_t encoder_get_cur_operand_offset(int opnd_id)
{
    return (uintptr_t)EncoderBase::getOpndLocation(opnd_id);
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_update_imm(int imm, char * stream) {
    Inst decInst;
    EncoderBase::Operands args;

    //Decode the instruction
    DecoderBase::decode(stream, &decInst);

    add_imm(args, decInst.operands[0].size(), imm, true/*is_signed*/);
    char* stream_next = (char *)EncoderBase::encode(stream, decInst.mn, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(decInst.mn, args);
    decodeThenPrint(stream);
#endif
    return stream_next;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem(Mnemonic m, OpndSize size,
               int disp, int base_reg, bool isBasePhysical, char * stream) {
    EncoderBase::Operands args;
    add_m(args, base_reg, disp, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_reg(Mnemonic m, OpndSize size,
               int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    if(m == Mnemonic_DIV || m == Mnemonic_IDIV || m == Mnemonic_MUL || m == Mnemonic_IMUL) {
      add_r(args, 0/*eax*/, size);
      add_r(args, 3/*edx*/, size);
    }
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
//! \brief Allows for different operand sizes
extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm_reg(Mnemonic m, OpndSize size,
                   int imm, int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    return encoder_imm_reg_diff_sizes(m, size, imm, size, reg, isPhysical, type, stream);
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_reg_reg_diff_sizes(Mnemonic m, OpndSize srcOpndSize,
                   int reg, bool isPhysical, OpndSize destOpndSize,
                   int reg2, bool isPhysical2, LowOpndRegType type, char * stream) {
    if((m == Mnemonic_MOV || m == Mnemonic_MOVQ || m == Mnemonic_MOVD) && reg == reg2) return stream;
    EncoderBase::Operands args;
    add_r(args, reg2, destOpndSize); //destination
    if(m == Mnemonic_SAL || m == Mnemonic_SHR || m == Mnemonic_SHL || m == Mnemonic_SAR)
      add_r(args, reg, OpndSize_8);
    else
      add_r(args, reg, srcOpndSize);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
//both operands have same size
extern "C" ENCODER_DECLARE_EXPORT char * encoder_reg_reg(Mnemonic m, OpndSize size,
                   int reg, bool isPhysical,
                   int reg2, bool isPhysical2, LowOpndRegType type, char * stream) {
    return encoder_reg_reg_diff_sizes(m, size, reg, isPhysical, size, reg2, isPhysical2, type, stream);
}
//! \brief Allows for different operand sizes
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_to_reg_diff_sizes(Mnemonic m, OpndSize memOpndSize,
                   int disp, int base_reg, bool isBasePhysical, OpndSize regOpndSize,
                   int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, regOpndSize);
    add_m(args, base_reg, disp, memOpndSize);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_reg(Mnemonic m, OpndSize size,
                   int disp, int base_reg, bool isBasePhysical,
                   int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    return encoder_mem_to_reg_diff_sizes(m, size, disp, base_reg, isBasePhysical, size, reg, isPhysical, type, stream);
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_scale_reg(Mnemonic m, OpndSize size,
                         int base_reg, bool isBasePhysical, int index_reg, bool isIndexPhysical, int scale,
                         int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, size);
    add_m_scale(args, base_reg, index_reg, scale, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_reg_mem_scale(Mnemonic m, OpndSize size,
                         int reg, bool isPhysical,
                         int base_reg, bool isBasePhysical, int index_reg, bool isIndexPhysical, int scale,
                         LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_m_scale(args, base_reg, index_reg, scale, size);
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
//! \brief Allows for different operand sizes
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_disp_scale_to_reg_diff_sizes(Mnemonic m, OpndSize memOpndSize,
                         int base_reg, bool isBasePhysical, int disp, int index_reg, bool isIndexPhysical, int scale,
                         OpndSize regOpndSize, int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, regOpndSize);
    add_m_disp_scale(args, base_reg, disp, index_reg, scale, memOpndSize);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_disp_scale_reg(Mnemonic m, OpndSize size,
                         int base_reg, bool isBasePhysical, int disp, int index_reg, bool isIndexPhysical, int scale,
                         int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    return encoder_mem_disp_scale_to_reg_diff_sizes(m, size, base_reg, isBasePhysical,
            disp, index_reg, isIndexPhysical, scale, size, reg, isPhysical,
            type, stream);
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_movzs_mem_disp_scale_reg(Mnemonic m, OpndSize size,
                         int base_reg, bool isBasePhysical, int disp, int index_reg, bool isIndexPhysical, int scale,
                         int reg, bool isPhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, OpndSize_32);
    add_m_disp_scale(args, base_reg, disp, index_reg, scale, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char* encoder_reg_mem_disp_scale(Mnemonic m, OpndSize size,
                         int reg, bool isPhysical,
                         int base_reg, bool isBasePhysical, int disp, int index_reg, bool isIndexPhysical, int scale,
                         LowOpndRegType type, char* stream) {
    EncoderBase::Operands args;
    add_m_disp_scale(args, base_reg, disp, index_reg, scale, size);
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_reg_mem(Mnemonic m, OpndSize size,
                   int reg, bool isPhysical,
                   int disp, int base_reg, bool isBasePhysical, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_m(args, base_reg, disp, size);
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    if (m == Mnemonic_CMPXCHG ){
       //CMPXCHG require EAX as args
       add_r(args,PhysicalReg_EAX,size);
       //Add lock prefix for CMPXCHG, guarantee the atomic of CMPXCHG in multi-core platform
       stream = (char *)EncoderBase::prefix(stream, InstPrefix_LOCK);
    }
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm_reg_diff_sizes (Mnemonic m, OpndSize sizeImm, int imm,
        OpndSize sizeReg, int reg, bool isPhysical, LowOpndRegType type, char * stream)
{
    //Create the operands
    EncoderBase::Operands args;
    //Add destination register
    add_r (args, reg, sizeReg);
    //For imul, we need to add implicit register explicitly
    if (m == Mnemonic_IMUL)
    {
        add_r (args, reg, sizeReg);
    }
    //Finally add the immediate
    add_imm (args, sizeImm, imm, true/*is_signed*/);

#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif

    //Now do the encoding
    stream = EncoderBase::encode (stream, m, args);

#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif

    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_update_imm_rm(int imm, char * stream) {
    Inst decInst;
    EncoderBase::Operands args;

    //Decode the instruction
    DecoderBase::decode(stream, &decInst);

    args.add(decInst.operands[0]);
    add_imm(args, decInst.operands[1].size(), imm, true/*is_signed*/);
    char* stream_next = (char *)EncoderBase::encode(stream, decInst.mn, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(decInst.mn, args);
    decodeThenPrint(stream);
#endif
    return stream_next;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm_mem(Mnemonic m, OpndSize size,
                   int imm,
                   int disp, int base_reg, bool isBasePhysical, char * stream) {
    return encoder_imm_mem_diff_sizes(m, size, imm, size, disp, base_reg, isBasePhysical, stream);
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm_mem_diff_sizes (Mnemonic m, OpndSize immOpndSize, int imm,
        OpndSize memOpndSize, int disp, int baseRegister, bool isBasePhysical, char * stream)
{
    //Add operands
    EncoderBase::Operands args;
    add_m (args, baseRegister, disp, memOpndSize);
    add_imm (args, immOpndSize, imm, true);

#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif

    //Do the encoding
    stream = EncoderBase::encode (stream, m, args);

#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif

    return stream;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_fp_mem(Mnemonic m, OpndSize size, int reg,
                  int disp, int base_reg, bool isBasePhysical, char * stream) {
    EncoderBase::Operands args;
    add_m(args, base_reg, disp, size);
    // a fake FP register as operand
    add_fp(args, reg, size == OpndSize_64/*is_double*/);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_mem_fp(Mnemonic m, OpndSize size,
                  int disp, int base_reg, bool isBasePhysical,
                  int reg, char * stream) {
    EncoderBase::Operands args;
    // a fake FP register as operand
    add_fp(args, reg, size == OpndSize_64/*is_double*/);
    add_m(args, base_reg, disp, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_return(char * stream) {
    EncoderBase::Operands args;
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, Mnemonic_RET, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(Mnemonic_RET, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_compare_fp_stack(bool pop, int reg, bool isDouble, char * stream) {
    Mnemonic m = pop ? Mnemonic_FUCOMIP : Mnemonic_FUCOMI;
    //a single operand or 2 operands?
    //FST ST(i) has a single operand in encoder.inl?
    EncoderBase::Operands args;
    add_fp(args, reg, isDouble);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, m, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(m, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_movez_mem_to_reg(OpndSize size,
                      int disp, int base_reg, bool isBasePhysical,
                      int reg, bool isPhysical, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, OpndSize_32);
    add_m(args, base_reg, disp, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, Mnemonic_MOVZX, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(Mnemonic_MOVZX, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_moves_mem_to_reg(OpndSize size,
                      int disp, int base_reg, bool isBasePhysical,
                      int reg, bool isPhysical, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg, OpndSize_32);
    add_m(args, base_reg, disp, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, Mnemonic_MOVSX, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(Mnemonic_MOVSX, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_movez_reg_to_reg(OpndSize size,
                      int reg, bool isPhysical, int reg2,
                      bool isPhysical2, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg2, OpndSize_32); //destination
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, Mnemonic_MOVZX, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(Mnemonic_MOVZX, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}
extern "C" ENCODER_DECLARE_EXPORT char * encoder_moves_reg_to_reg(OpndSize size,
                      int reg, bool isPhysical,int reg2,
                      bool isPhysical2, LowOpndRegType type, char * stream) {
    EncoderBase::Operands args;
    add_r(args, reg2, OpndSize_32); //destination
    add_r(args, reg, size);
#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif
    stream = (char *)EncoderBase::encode(stream, Mnemonic_MOVSX, args);
#ifdef PRINT_ENCODER_STREAM
    printEncoderInst(Mnemonic_MOVSX, args);
    decodeThenPrint(stream_start);
#endif
    return stream;
}

extern "C" ENCODER_DECLARE_EXPORT char * encoder_imm_reg_reg (Mnemonic m, int imm, OpndSize immediateSize,
        int sourceReg, OpndSize sourceRegSize, int destReg, OpndSize destRegSize, char * stream)
{
    EncoderBase::Operands args;

    //Add the source and destination registers
    add_r (args, destReg, destRegSize);
    add_r (args, sourceReg, sourceRegSize);

    //Now add the immediate. We expect in three operand situation that immediate is last argument
    add_imm (args, immediateSize, imm, true/*is_signed*/);

#ifdef PRINT_ENCODER_STREAM
    char* stream_start = stream;
#endif

    //Do the actual encoding
    stream = EncoderBase::encode (stream, m, args);

#ifdef PRINT_ENCODER_STREAM
    printEncoderInst (m, args);
    decodeThenPrint (stream_start);
#endif

    //Return the updated stream pointer
    return stream;
}

/**
 * @brief Generates variable sized nop instructions.
 * @param numBytes Number of bytes for the nop instruction. If this value is
 * larger than 9 bytes, more than one nop instruction will be generated.
 * @param stream Instruction stream where to place the nops
 * @return Updated instruction stream pointer after generating the nops
 */
extern "C" ENCODER_DECLARE_EXPORT char * encoder_nops(unsigned numBytes, char * stream) {
    return EncoderBase::nops(stream, numBytes);
}

// Disassemble the operand "opnd" and put the readable format in "strbuf"
// up to a string length of "len".
unsigned int DisassembleOperandToBuf(const EncoderBase::Operand& opnd, char* strbuf, unsigned int len)
{
    unsigned int sz = 0;
    if(opnd.size() != OpndSize_32) {
        const char * opndSizeString = getOpndSizeString(opnd.size());

        if (opndSizeString == NULL) {
            // If the string that represents operand size is null it means that
            // the operand size is an invalid value. Although this could be a
            // problem if instruction is corrupted, technically failing to
            // disassemble is not fatal. Thus, let's warn but proceed with using
            // an empty string.
            ALOGW("JIT-WARNING: Cannot decode instruction operand size.");
            opndSizeString = "";
        }

        sz += snprintf(&strbuf[sz], len-sz, "%s ", opndSizeString);
    }
    if(opnd.is_mem()) {
        if(opnd.scale() != 0) {
            sz += snprintf(&strbuf[sz], len-sz, "%d(%s,%s,%d)", opnd.disp(),
                           getRegNameString(opnd.base()),
                           getRegNameString(opnd.index()), opnd.scale());
        } else {
            sz += snprintf(&strbuf[sz], len-sz, "%d(%s)",
                           opnd.disp(), getRegNameString(opnd.base()));
        }
    } else if(opnd.is_imm()) {
        sz += snprintf(&strbuf[sz], len-sz, "#%x", (int)opnd.imm());
    } else if(opnd.is_reg()) {
        sz += snprintf(&strbuf[sz], len-sz, "%s",
                       getRegNameString(opnd.reg()));
    }
    return sz;
}

// Disassemble the instruction "decInst" and put the readable format
// in "strbuf" up to a string length of "len".
void DisassembleInstToBuf(Inst& decInst, char* strbuf, unsigned int len)
{
    unsigned int sz = 0;
    int k;
    sz += snprintf(&strbuf[sz], len-sz, "%s ", EncoderBase::toStr(decInst.mn));
    if (decInst.argc > 0) {
        sz += DisassembleOperandToBuf(decInst.operands[decInst.argc-1],
                                 &strbuf[sz], len-sz);
        for(k = decInst.argc-2; k >= 0; k--) {
            sz += snprintf(&strbuf[sz], len-sz, ", ");
            sz += DisassembleOperandToBuf(decInst.operands[k], &strbuf[sz], len-sz);
        }
    }
}

// Disassmble the x86 instruction pointed to by code pointer "stream."
// Put the disassemble text in the "strbuf" up to string length "len".
// Return the code pointer after the disassemble x86 instruction.
extern "C" ENCODER_DECLARE_EXPORT
char* decoder_disassemble_instr(char* stream, char* strbuf, unsigned int len)
{
    Inst decInst;
    unsigned numBytes = DecoderBase::decode(stream, &decInst);
    DisassembleInstToBuf(decInst, strbuf, len);
    return (stream + numBytes);
}

/**
 * @brief Physical register char* counterparts
 */
static const char * PhysicalRegString[] = { "eax", "ebx", "ecx", "edx", "edi",
        "esi", "esp", "ebp", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
        "xmm6", "xmm7", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        "null"
        };

/**
 * @brief Scratch register char* counterparts
 */
static const char * ScratchRegString[] = { "scratch1", "scratch2", "scratch3",
        "scratch4", "scratch5", "scratch6", "scratch7", "scratch8", "scratch9",
        "scratch10" };

extern "C" ENCODER_DECLARE_EXPORT
/**
 * @brief Transform a physical register into its char* counterpart
 * @param reg the PhysicalReg we want to have a char* equivalent
 * @return the register reg in char* form
 */
const char * physicalRegToString(PhysicalReg reg)
{
    if (reg < PhysicalReg_Null) {
        return PhysicalRegString[reg];
    } else if (reg >= PhysicalReg_SCRATCH_1 && reg <= PhysicalReg_SCRATCH_10) {
        return ScratchRegString[reg - PhysicalReg_SCRATCH_1];
    } else if (reg == PhysicalReg_Null) {
        return "null";
    } else {
        return "corrupted-data";
    }
}
