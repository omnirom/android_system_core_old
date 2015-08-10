/* libs/pixelflinger/codeflinger/x86/X86Assembler.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "X86Assembler"

#include <stdio.h>
#include <stdlib.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <string.h>

#if defined(WITH_LIB_HARDWARE)
#include <hardware_legacy/qemu_tracing.h>
#endif

#include <private/pixelflinger/ggl_context.h>

#include "codeflinger/CodeCache.h"
#include "codeflinger/x86/X86Assembler.h"

// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------

X86Assembler::X86Assembler(const sp<Assembly>& assembly)
    :  mAssembly(assembly)
{
    mBase = mStream = (char *)assembly->base();
    mDuration = ggl_system_time();
#if defined(WITH_LIB_HARDWARE)
    mQemuTracing = true;
#endif
}

X86Assembler::~X86Assembler()
{
}

char* X86Assembler::pc() const
{
    return mStream;
}

char* X86Assembler::base() const
{
    return mBase;
}

void X86Assembler::reset()
{
    mBase = mStream = (char *)mAssembly->base();
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
}

// ----------------------------------------------------------------------------

void X86Assembler::disassemble(const char* name)
{
    if (name) {
        printf("%s:\n", name);
    }
    size_t count = pc()-base();
    unsigned insLength;
    unsigned insSize;
    char* curStream = (char*)base();
    while (count>0) {
        ssize_t label = mLabelsInverseMapping.indexOfKey(curStream);
        if (label >= 0) {
            printf("%s:\n", mLabelsInverseMapping.valueAt(label));
        }
        ssize_t comment = mComments.indexOfKey(curStream);
        if (comment >= 0) {
            printf("; %s\n", mComments.valueAt(comment));
        }
        insLength = decodeThenPrint(curStream);
        curStream = curStream + insLength;
        count = count - insLength;
    }
}

void X86Assembler::comment(const char* string)
{
    mComments.add(mStream, string);
}

void X86Assembler::label(const char* theLabel)
{
    mLabels.add(theLabel, mStream);
    mLabelsInverseMapping.add(mStream, theLabel);
}

//the conditional jump
void X86Assembler::JCC(Mnemonic cc, const char* label) {
    switch (cc) {
    case Mnemonic_JO:
        encoder_imm(Mnemonic_JO, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNO:
        encoder_imm(Mnemonic_JNO, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JB:
        encoder_imm(Mnemonic_JB, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNB:
        encoder_imm(Mnemonic_JNB, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JZ:
        encoder_imm(Mnemonic_JZ, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNZ:
        encoder_imm(Mnemonic_JNZ, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JBE:
        encoder_imm(Mnemonic_JBE, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNBE:
        encoder_imm(Mnemonic_JNBE, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JS:
        encoder_imm(Mnemonic_JS, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNS:
        encoder_imm(Mnemonic_JNS, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JP:
        encoder_imm(Mnemonic_JP, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNP:
        encoder_imm(Mnemonic_JNP, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JL:
        encoder_imm(Mnemonic_JL, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNL:
        encoder_imm(Mnemonic_JNL, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JLE:
        encoder_imm(Mnemonic_JLE, OpndSize_32,  0/*imm*/, mStream);
        break;
    case Mnemonic_JNLE:
        encoder_imm(Mnemonic_JNLE, OpndSize_32,  0/*imm*/, mStream);
        break;
    default :
        printf("the condition is not supported.\n");
        return;
    }
    mStreamNext = mStream + encoder_get_inst_size(mStream);
    //the offset is relative to the next instruction of the current PC
    mBranchTargets.add(branch_target_t(label, mStream, mStreamNext));
    mStream = mStreamNext;
}

void X86Assembler::JMP(const char* label) {
    encoder_imm(Mnemonic_JMP, OpndSize_32,  0/*imm*/, mStream);
    mStreamNext = mStream + encoder_get_inst_size(mStream);
    mBranchTargets.add(branch_target_t(label, mStream, mStreamNext));
    mStream = mStreamNext;
}

void X86Assembler::prepare_esp(int old_offset)
{
    mStreamUpdate = mStream;
    SUB_IMM_TO_REG(old_offset, ESP);
}

void X86Assembler::update_esp(int new_offset)
{
    encoder_update_imm_rm(new_offset, mStreamUpdate);
}

void X86Assembler::shrink_esp(int shrink_offset)
{
    ADD_IMM_TO_REG(shrink_offset, ESP);
}

void X86Assembler::callee_work()
{
    //push EBX, ESI, EDI which need to be done in callee
    /*
    push %ebp
    mov  %esp,%ebp
    push %ebx
    push %esi
    push %edi
    */
    PUSH(EBP);
    MOV_REG_TO_REG(ESP, EBP);
    PUSH(EBX);
    PUSH(ESI);
    PUSH(EDI);
}

void X86Assembler::return_work()
{
// pop  %esi
// pop  %edi
// pop  %ebx
// movl %ebp,%esp
// pop  %ebp
// ret
// ret is equivalent to below
// pop  %eax  // the return address
// jmp  *%eax
    POP(EDI);
    POP(ESI);
    POP(EBX);
    POP(EBP);
    encoder_return(mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

int X86Assembler::generate(const char* name)
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--) {
        const branch_target_t& bt = mBranchTargets[count];
        char* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                            "error resolving branch targets, target_pc is null");
        //the offset is relative to the next instruction of the current PC
        int32_t offset = int32_t(target_pc - bt.next_pc);
        encoder_update_imm(offset, bt.pc);
    }

    mAssembly->resize((int)(pc()-base()));

    // the instruction cache is flushed by CodeCache
    const int64_t duration = ggl_system_time() - mDuration;
    const char * const format = "generated %s (%d ins size) at [%p:%p] in %lld ns\n";
    ALOGI(format, name, int(pc()-base()), base(), pc(), duration);

#if defined(WITH_LIB_HARDWARE)
    if (__builtin_expect(mQemuTracing, 0)) {
        int err = qemu_add_mapping(uintptr_t(base()), name);
        mQemuTracing = (err >= 0);
    }
#endif

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.pf.disasm", value, "0");
    if (atoi(value) != 0) {
        printf(format, name, int(pc()-base()), base(), pc(), duration);
        disassemble(name);
    }

    return NO_ERROR;
}

char* X86Assembler::pcForLabel(const char* label)
{
    return mLabels.valueFor(label);
}

// ----------------------------------------------------------------------------

void X86Assembler::PUSH(int reg) {
    encoder_reg(Mnemonic_PUSH, OpndSize_32, reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::POP(int reg) {
    encoder_reg(Mnemonic_POP, OpndSize_32, reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

//arithmetic
void X86Assembler::ADD_REG_TO_REG(int src, int dst) {
    encoder_reg_reg(Mnemonic_ADD, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ADD_IMM_TO_REG(int imm, int dst) {
    encoder_imm_reg(Mnemonic_ADD, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ADD_IMM_TO_MEM(int imm, int disp, int dst) {
    encoder_imm_mem(Mnemonic_ADD, OpndSize_32, imm, disp, dst, 0/*isBasePhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ADD_MEM_TO_REG(int base_reg, int disp, int dst) {
    encoder_mem_reg(Mnemonic_ADD, OpndSize_32, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ADD_REG_TO_MEM(int src, int base_reg, int disp) {
    encoder_reg_mem(Mnemonic_ADD, OpndSize_32, src, 0/*isPhysical*/, disp, base_reg, 0/*isBasePhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SUB_REG_TO_REG(int src, int dst) {
    encoder_reg_reg(Mnemonic_SUB, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SUB_IMM_TO_REG(int imm, int dst) {
    encoder_imm_reg(Mnemonic_SUB, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SUB_IMM_TO_MEM(int imm, int disp, int dst) {
    encoder_imm_mem(Mnemonic_SUB, OpndSize_32, imm, disp, dst, 0/*isBasePhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SUB_REG_TO_MEM(int src, int base_reg, int disp) {
    encoder_reg_mem(Mnemonic_SUB, OpndSize_32, src, 0/*isPhysical*/, disp, base_reg, 0/*isBasePhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

//test
void X86Assembler::TEST_REG_TO_REG(int src, int dst, OpndSize size) {
    encoder_reg_reg(Mnemonic_TEST, size, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

//compare
void X86Assembler::CMP_REG_TO_REG(int src, int dst, OpndSize size) {
    encoder_reg_reg(Mnemonic_CMP, size, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::CMP_IMM_TO_REG(int imm, int dst) {
    encoder_imm_reg(Mnemonic_CMP, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::CMP_MEM_TO_REG(int base_reg, int disp, int dst, OpndSize size) {
    encoder_mem_reg(Mnemonic_CMP, size, disp, base_reg, 0/*isBasePhysical*/,
                    dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::CMP_REG_TO_MEM(int reg, int disp, int base_reg, OpndSize size)
{
    encoder_reg_mem(Mnemonic_CMP, size, reg, 0/*isPhysical*/, disp, base_reg, 0/*isBasePhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

//logical
void X86Assembler::AND_REG_TO_REG(int src, int dst) {
    encoder_reg_reg(Mnemonic_AND, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::AND_IMM_TO_REG(int imm, int dst) {
    encoder_imm_reg(Mnemonic_AND, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::OR_REG_TO_REG(int src, int dst) {
    encoder_reg_reg(Mnemonic_OR, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::XOR(int src, int dst) {
    encoder_reg_reg(Mnemonic_XOR, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::OR_IMM_TO_REG(int imm, int dst) {
    encoder_imm_reg(Mnemonic_OR, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::NOT(int dst) {
    encoder_reg(Mnemonic_NOT, OpndSize_32, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::NEG(int dst) {
    encoder_reg(Mnemonic_NEG, OpndSize_32, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}
//shift
void X86Assembler::SHL(int imm, int dst) {
    encoder_imm_reg(Mnemonic_SHL, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SHL(int imm, int disp, int dst) {
    encoder_imm_mem(Mnemonic_SHL, OpndSize_32, imm, disp, dst, 0/*isBasePhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SHR(int imm, int dst) {
    encoder_imm_reg(Mnemonic_SHR, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SHR(int imm, int disp, int dst) {
    encoder_imm_mem(Mnemonic_SHR, OpndSize_32, imm, disp, dst, 0/*isBasePhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::SAR(int imm, int dst) {
    encoder_imm_reg(Mnemonic_SAR, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ROR(const int imm, int dst) {
    encoder_imm_reg(Mnemonic_ROR, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::ROR(int imm, int disp, int dst) {
    encoder_imm_mem(Mnemonic_ROR, OpndSize_32, imm, disp, dst, 0/*isBasePhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}
//signed extension
void X86Assembler::MOVSX_MEM_TO_REG(OpndSize size, int base_reg, int disp, int dst) {
    encoder_moves_mem_to_reg(size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOVSX_REG_TO_REG(OpndSize size, int src, int dst) {
    encoder_moves_reg_to_reg(size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}
//zero entension
void X86Assembler::MOVZX_MEM_TO_REG(OpndSize size, int base_reg, int disp, int dst) {
    encoder_movez_mem_to_reg(size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOVZX_REG_TO_REG(OpndSize size, int src, int dst) {
    encoder_movez_reg_to_reg(size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

// multiply...
// the first source operand is placed in EAX
void X86Assembler::IMUL(int reg) {
    encoder_reg(Mnemonic_IMUL, OpndSize_32, reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::IMUL(int src, int dst) {
    encoder_reg_reg(Mnemonic_IMUL, OpndSize_32, src, 0/*isPhysical*/, dst/*dst is the destination*/, 0/*isPhysical2*/,LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MUL(int reg) {
    encoder_reg(Mnemonic_MUL, OpndSize_32, reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}


// data transfer...
void X86Assembler::MOV_IMM_TO_REG(int32_t imm, int dst) {
    encoder_imm_reg(Mnemonic_MOV, OpndSize_32, imm, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOV_REG_TO_REG(int src, int dst, OpndSize size)
{
    if(src == dst) return;
    encoder_reg_reg(Mnemonic_MOV, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOV_REG_TO_MEM(int reg, int disp, int base_reg, OpndSize size)
{
    encoder_reg_mem(Mnemonic_MOV, size, reg, 0/*isPhysical*/, disp, base_reg, 0/*isBasePhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOV_MEM_TO_REG(int disp, int base_reg, int reg, OpndSize size)
{
    encoder_mem_reg(Mnemonic_MOV, size, disp, base_reg, 0/*isBasePhysical*/,
                    reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::MOV_MEM_SCALE_TO_REG(int base_reg, int index_reg, int scale, int reg, OpndSize size)
{
    encoder_mem_scale_reg(Mnemonic_MOV, size, base_reg, 0/*isBasePhysical*/, index_reg, 0/*isIndexPhysical*/, scale, reg, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
    mStream = mStream + encoder_get_inst_size(mStream);
}
// the conditional move
void X86Assembler::CMOV_REG_TO_REG(Mnemonic cc, int src, int dst, OpndSize size)
{
    switch (cc) {
    case Mnemonic_CMOVO:
        encoder_reg_reg(Mnemonic_CMOVO, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNO:
        encoder_reg_reg(Mnemonic_CMOVNO, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVB:
        encoder_reg_reg(Mnemonic_CMOVB, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNB:
        encoder_reg_reg(Mnemonic_CMOVNB, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVZ:
        encoder_reg_reg(Mnemonic_CMOVZ, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNZ:
        encoder_reg_reg(Mnemonic_CMOVNZ, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVBE:
        encoder_reg_reg(Mnemonic_CMOVBE, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNBE:
        encoder_reg_reg(Mnemonic_CMOVNBE, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVS:
        encoder_reg_reg(Mnemonic_CMOVS, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNS:
        encoder_reg_reg(Mnemonic_CMOVNS, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVP:
        encoder_reg_reg(Mnemonic_CMOVP, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNP:
        encoder_reg_reg(Mnemonic_CMOVNP, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVL:
        encoder_reg_reg(Mnemonic_CMOVL, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNL:
        encoder_reg_reg(Mnemonic_CMOVNL, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVLE:
        encoder_reg_reg(Mnemonic_CMOVLE, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNLE:
        encoder_reg_reg(Mnemonic_CMOVNLE, size, src, 0/*isPhysical*/, dst, 0/*isPhysical2*/, LowOpndRegType_gp, mStream);
        break;
    default :
        printf("the condition is not supported.\n");
        return;
    }
    mStream = mStream + encoder_get_inst_size(mStream);
}

void X86Assembler::CMOV_MEM_TO_REG(Mnemonic cc, int disp, int base_reg, int dst, OpndSize size)
{
    switch (cc) {
    case Mnemonic_CMOVO:
        encoder_mem_reg(Mnemonic_CMOVO, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNO:
        encoder_mem_reg(Mnemonic_CMOVNO, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVB:
        encoder_mem_reg(Mnemonic_CMOVB, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNB:
        encoder_mem_reg(Mnemonic_CMOVNB, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVZ:
        encoder_mem_reg(Mnemonic_CMOVZ, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNZ:
        encoder_mem_reg(Mnemonic_CMOVNZ, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVBE:
        encoder_mem_reg(Mnemonic_CMOVBE, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNBE:
        encoder_mem_reg(Mnemonic_CMOVNBE, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVS:
        encoder_mem_reg(Mnemonic_CMOVS, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNS:
        encoder_mem_reg(Mnemonic_CMOVNS, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVP:
        encoder_mem_reg(Mnemonic_CMOVP, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNP:
        encoder_mem_reg(Mnemonic_CMOVNP, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVL:
        encoder_mem_reg(Mnemonic_CMOVL, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNL:
        encoder_mem_reg(Mnemonic_CMOVNL, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVLE:
        encoder_mem_reg(Mnemonic_CMOVLE, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    case Mnemonic_CMOVNLE:
        encoder_mem_reg(Mnemonic_CMOVNLE, size, disp, base_reg, 0/*isBasePhysical*/, dst, 0/*isPhysical*/, LowOpndRegType_gp, mStream);
        break;
    default :
        printf("the condition is not supported.\n");
        return;
    }
    mStream = mStream + encoder_get_inst_size(mStream);
}

}; // namespace android
