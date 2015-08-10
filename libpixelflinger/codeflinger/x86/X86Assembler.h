/* libs/pixelflinger/codeflinger/x86/X86Assembler.h
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

#ifndef ANDROID_X86ASSEMBLER_H
#define ANDROID_X86ASSEMBLER_H

#include <stdint.h>
#include <sys/types.h>

#include <utils/Vector.h>
#include <utils/KeyedVector.h>

#include "codeflinger/tinyutils/smartpointer.h"
#include "codeflinger/CodeCache.h"
#include "enc_wrapper.h"

namespace android {

// ----------------------------------------------------------------------------

class X86Assembler
{
public:

    enum {
        EAX = PhysicalReg_EAX, EBX = PhysicalReg_EBX, ECX = PhysicalReg_ECX,
        EDX = PhysicalReg_EDX, EDI = PhysicalReg_EDI, ESI = PhysicalReg_ESI,
        ESP = PhysicalReg_ESP, EBP = PhysicalReg_EBP
    };

    X86Assembler(const sp<Assembly>& assembly);
    ~X86Assembler();

    char*   base() const;
    char*   pc() const;


    void        disassemble(const char* name);

    // ------------------------------------------------------------------------
    // X86AssemblerInterface...
    // ------------------------------------------------------------------------

    void    reset();

    int     generate(const char* name);

    void    comment(const char* string);

    void    label(const char* theLabel);

    void    JCC(Mnemonic cc, const char* label);

    void    JMP(const char* label);

    void    prepare_esp(int old_offset);

    void    update_esp(int new_offset);

    void    shrink_esp(int shrink_offset);

    void    callee_work();

    void    return_work();

    char*   pcForLabel(const char* label);

    void    PUSH(int reg);

    void    POP(int reg);

    void    ADD_REG_TO_REG(int src, int dst);
    void    ADD_IMM_TO_REG(int imm, int dst);
    void    ADD_IMM_TO_MEM(int imm, int disp, int dst);
    void    ADD_MEM_TO_REG(int base_reg, int disp, int dst);
    void    ADD_REG_TO_MEM(int src, int base_reg, int disp);
    void    SUB_REG_TO_REG(int src, int dst);
    void    SUB_IMM_TO_REG(int imm, int dst);
    void    SUB_IMM_TO_MEM(int imm, int disp, int dst);
    void    SUB_REG_TO_MEM(int src, int base_reg, int disp);

    void    TEST_REG_TO_REG(int src, int dst, OpndSize size=OpndSize_32);
    void    CMP_REG_TO_REG(int src, int dst, OpndSize size=OpndSize_32);
    void    CMP_MEM_TO_REG(int base_reg, int disp, int dst, OpndSize size=OpndSize_32);
    void    CMP_REG_TO_MEM(int reg, int disp, int base_reg, OpndSize size=OpndSize_32);
    void    CMP_IMM_TO_REG(int imm, int dst);

    void    AND_REG_TO_REG(int src, int dst);
    void    AND_IMM_TO_REG(int imm, int dst);
    void    OR_REG_TO_REG(int src, int dst);
    void    XOR(int src, int dst);
    void    OR_IMM_TO_REG(int imm, int dst);
    void    NOT(int dst);
    void    NEG(int dst);
    void    SHL(int imm, int dst);
    void    SHL(int imm, int disp, int dst);
    void    SHR(int imm, int dst);
    void    SHR(int imm, int disp, int dst);
    void    SAR(int imm, int dst);
    void    ROR(const int imm, int dst);
    void    ROR(int imm, int disp, int dst);
    void    IMUL(int reg);
    void    IMUL(int src, int dst);
    void    MUL(int reg);

    void    MOVSX_MEM_TO_REG(OpndSize size, int base_reg, int disp, int dst);
    void    MOVSX_REG_TO_REG(OpndSize size, int src, int dst);
    void    MOVZX_MEM_TO_REG(OpndSize size, int base_reg, int disp, int dst);
    void    MOVZX_REG_TO_REG(OpndSize size, int src, int dst);
    void    MOV_IMM_TO_REG(int32_t imm, int dst);
    void    MOV_REG_TO_REG(int src, int dst, OpndSize size=OpndSize_32);
    void    MOV_MEM_TO_REG(int disp, int base_reg, int reg, OpndSize size=OpndSize_32);
    void    MOV_REG_TO_MEM(int reg, int disp, int base_reg, OpndSize size=OpndSize_32);
    void    MOV_MEM_SCALE_TO_REG(int base_reg, int index_reg, int scale, int reg, OpndSize size=OpndSize_32);
    void    CMOV_REG_TO_REG(Mnemonic cc, int src, int dst, OpndSize size=OpndSize_32);
    void    CMOV_MEM_TO_REG(Mnemonic cc, int disp, int base_reg, int dst, OpndSize size=OpndSize_32);


    sp<Assembly>    mAssembly;
    char*           mBase;
    char*           mStream;
    //branch target offset is relative to the next instruction
    char*           mStreamNext;
    //updating esp after iterating the loop
    char*           mStreamUpdate;

    int64_t         mDuration;
#if defined(WITH_LIB_HARDWARE)
    bool            mQemuTracing;
#endif

    struct branch_target_t {
        inline branch_target_t() : label(0), pc(0), next_pc(0) { }
        inline branch_target_t(const char* l, char* p, char* next_p)
            : label(l), pc(p), next_pc(next_p) { }
        const char* label;
        char*   pc;
        char*   next_pc;
    };

    Vector<branch_target_t>             mBranchTargets;
    KeyedVector< const char*, char* >   mLabels;
    KeyedVector< char*, const char* >   mLabelsInverseMapping;
    KeyedVector< char*, const char* >   mComments;
};

}; // namespace android

#endif //ANDROID_X86ASSEMBLER_H
