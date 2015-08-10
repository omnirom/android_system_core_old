/* libs/pixelflinger/codeflinger/x86/texturing.cpp
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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include <cutils/log.h>

#include "codeflinger/x86/GGLX86Assembler.h"


namespace android {

// ---------------------------------------------------------------------------

// iterators are initialized like this:
// (intToFixedCenter(x) * dx)>>16 + x0
// ((x<<16 + 0x8000) * dx)>>16 + x0
// ((x<<16)*dx + (0x8000*dx))>>16 + x0
// ( (x*dx) + dx>>1 ) + x0
// (x*dx) + (dx>>1 + x0)

void GGLX86Assembler::init_iterated_color(fragment_parts_t& parts, const reg_t& x)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;
    int temp_reg;

    if (mSmooth) {
        // NOTE: we could take this case in the mDithering + !mSmooth case,
        // but this would use up to 4 more registers for the color components
        // for only a little added quality.
        // Currently, this causes the system to run out of registers in
        // some case (see issue #719496)

        comment("compute initial iterated color (smooth and/or dither case)");

        parts.iterated_packed = 0;
        parts.packed = 0;

        // 0x1: color component
        // 0x2: iterators
        //parts.reload = 3;
        const int optReload = mOptLevel >> 1;
        if (optReload >= 3)         parts.reload = 0; // reload nothing
        else if (optReload == 2)    parts.reload = 2; // reload iterators
        else if (optReload == 1)    parts.reload = 1; // reload colors
        else if (optReload <= 0)    parts.reload = 3; // reload both

        if (!mSmooth) {
            // we're not smoothing (just dithering), we never have to
            // reload the iterators
            parts.reload &= ~2;
        }

        Scratch scratches(registerFile());
        const int t0 = (parts.reload & 1) ? scratches.obtain() : 0;
        const int t1 = (parts.reload & 2) ? scratches.obtain() : 0;
        for (int i=0 ; i<4 ; i++) {
            if (!mInfo[i].iterated)
                continue;
            // this component exists in the destination and is not replaced
            // by a texture unit.
            const int c = (parts.reload & 1) ? t0 : obtainReg();
            if (i==0) CONTEXT_LOAD(c, iterators.ydady);
            if (i==1) CONTEXT_LOAD(c, iterators.ydrdy);
            if (i==2) CONTEXT_LOAD(c, iterators.ydgdy);
            if (i==3) CONTEXT_LOAD(c, iterators.ydbdy);
            parts.argb[i].reg = c;

            if (mInfo[i].smooth) {
                parts.argb_dx[i].reg = (parts.reload & 2) ? t1 : obtainReg();
                const int dvdx = parts.argb_dx[i].reg;
                temp_reg = scratches.obtain();
                CONTEXT_LOAD(dvdx, generated_vars.argb[i].dx);
                MOV_REG_TO_REG(dvdx, temp_reg);
                IMUL(x.reg, temp_reg);
                ADD_REG_TO_REG(temp_reg, c);
                scratches.recycle(temp_reg);

                // adjust the color iterator to make sure it won't overflow
                if (!mAA) {
                    // this is not needed when we're using anti-aliasing
                    // because we will (have to) clamp the components
                    // anyway.
                    int end = scratches.obtain();
                    MOV_MEM_TO_REG(parts.count.offset_ebp, PhysicalReg_EBP, end);
                    SHR(16, end);
                    IMUL(end, dvdx);
                    temp_reg = end;
                    // c - (dvdx*end + c) = -(dvdx*end)
                    MOV_REG_TO_REG(dvdx, temp_reg);
                    NEG(temp_reg);
                    ADD_REG_TO_REG(c, dvdx);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, temp_reg, c);
                    /*
                                        SUB_REG_TO_REG(dvdx, temp_reg);
                                        switch(i) {
                                        case 0:
                                            JCC(Mnemonic_JNS, "1f_init_iterated_color");
                                            SUB_REG_TO_REG(dvdx, c);
                                            label("1f_init_iterated_color");
                                            break;
                                        case 1:
                                            JCC(Mnemonic_JNS, "2f_init_iterated_color");
                                            SUB_REG_TO_REG(dvdx, c);
                                            label("2f_init_iterated_color");
                                            break;
                                        case 2:
                                            JCC(Mnemonic_JNS, "3f_init_iterated_color");
                                            SUB_REG_TO_REG(dvdx, c);
                                            label("3f_init_iterated_color");
                                            break;
                                        case 3:
                                            JCC(Mnemonic_JNS, "4f_init_iterated_color");
                                            SUB_REG_TO_REG(dvdx, c);
                                            label("4f_init_iterated_color");
                                            break;
                                        }
                    */

                    MOV_REG_TO_REG(c, temp_reg);
                    SAR(31, temp_reg);
                    NOT(temp_reg);
                    AND_REG_TO_REG(temp_reg, c);
                    scratches.recycle(end);
                }
                if(parts.reload & 2)
                    scratches.recycle(dvdx);
                else
                    recycleReg(dvdx);
            }
            CONTEXT_STORE(c, generated_vars.argb[i].c);
            if(parts.reload & 1)
                scratches.recycle(parts.argb[i].reg);
            else
                recycleReg(parts.argb[i].reg);

            parts.argb[i].reg = -1;
            //if (parts.reload & 1) {
            //    //MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
            //}
        }
    } else {
        // We're not smoothed, so we can
        // just use a packed version of the color and extract the
        // components as needed (or not at all if we don't blend)

        // figure out if we need the iterated color
        int load = 0;
        for (int i=0 ; i<4 ; i++) {
            component_info_t& info = mInfo[i];
            if ((info.inDest || info.needed) && !info.replaced)
                load |= 1;
        }

        parts.iterated_packed = 1;
        parts.packed = (!mTextureMachine.mask && !mBlending
                        && !mFog && !mDithering);
        parts.reload = 0;
        if (load || parts.packed) {
            if (mBlending || mDithering || mInfo[GGLFormat::ALPHA].needed) {
                comment("load initial iterated color (8888 packed)");
                parts.iterated.setTo(obtainReg(),
                                     &(c->formats[GGL_PIXEL_FORMAT_RGBA_8888]));
                CONTEXT_LOAD(parts.iterated.reg, packed8888);
            } else {
                comment("load initial iterated color (dest format packed)");

                parts.iterated.setTo(obtainReg(), &mCbFormat);

                // pre-mask the iterated color
                const int bits = parts.iterated.size();
                const uint32_t size = ((bits>=32) ? 0 : (1LU << bits)) - 1;
                uint32_t mask = 0;
                if (mMasking) {
                    for (int i=0 ; i<4 ; i++) {
                        const int component_mask = 1<<i;
                        const int h = parts.iterated.format.c[i].h;
                        const int l = parts.iterated.format.c[i].l;
                        if (h && (!(mMasking & component_mask))) {
                            mask |= ((1<<(h-l))-1) << l;
                        }
                    }
                }

                if (mMasking && ((mask & size)==0)) {
                    // none of the components are present in the mask
                } else {
                    CONTEXT_LOAD(parts.iterated.reg, packed);
                    if (mCbFormat.size == 1) {
                        int imm = 0xFF;
                        AND_IMM_TO_REG(imm, parts.iterated.reg);
                    } else if (mCbFormat.size == 2) {
                        SHR(16, parts.iterated.reg);
                    }
                }

                // pre-mask the iterated color
                if (mMasking) {
                    //AND_IMM_TO_REG(mask, parts.iterated.reg);
                    build_and_immediate(parts.iterated.reg, parts.iterated.reg,
                                        mask, bits);
                }
            }
            mCurSp = mCurSp - 4;
            parts.iterated.offset_ebp = mCurSp;
            MOV_REG_TO_MEM(parts.iterated.reg, parts.iterated.offset_ebp, EBP);
            //PUSH(parts.iterated.reg);
            recycleReg(parts.iterated.reg);
            parts.iterated.reg=-1;
        }
    }
}

void GGLX86Assembler::build_iterated_color(
    component_t& fragment,
    fragment_parts_t& parts,
    int component,
    Scratch& regs)
{

    if (!mInfo[component].iterated)
        return;

    if (parts.iterated_packed) {
        // iterated colors are packed, extract the one we need
        parts.iterated.reg = regs.obtain();
        MOV_MEM_TO_REG(parts.iterated.offset_ebp, EBP, parts.iterated.reg);
        extract(fragment, parts.iterated, component);
        regs.recycle(parts.iterated.reg);
    } else {
        fragment.h = GGL_COLOR_BITS;
        fragment.l = GGL_COLOR_BITS - 8;
        fragment.flags |= CLEAR_LO;
        // iterated colors are held in their own register,
        // (smooth and/or dithering case)
        Scratch scratches(registerFile());
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        if (parts.reload==3) {
            // this implies mSmooth
            int dx = scratches.obtain();
            CONTEXT_LOAD(fragment.reg, generated_vars.argb[component].c);
            CONTEXT_LOAD(dx, generated_vars.argb[component].dx);
            ADD_REG_TO_REG(fragment.reg, dx);
            CONTEXT_STORE(dx, generated_vars.argb[component].c);
            scratches.recycle(dx);
        } else if (parts.reload & 1) {
            //MOV_MEM_TO_REG(parts.argb[component].offset_ebp, EBP, fragment.reg);
            CONTEXT_LOAD(fragment.reg, generated_vars.argb[component].c);
        } else {
            // we don't reload, so simply rename the register and mark as
            // non CORRUPTIBLE so that the texture env or blending code
            // won't modify this (renamed) register
            //regs.recycle(fragment.reg);
            //MOV_MEM_TO_REG(parts.argb[component].offset_ebp, EBP, fragment.reg);
            // it will also be used in build_smooth_shade
            CONTEXT_LOAD(fragment.reg, generated_vars.argb[component].c);
            //fragment.reg = parts.argb[component].reg;
            //fragment.flags &= ~CORRUPTIBLE;
        }
        scratches.recycle(mBuilderContext.Rctx);
        if (mInfo[component].smooth && mAA) {
            // when using smooth shading AND anti-aliasing, we need to clamp
            // the iterators because there is always an extra pixel on the
            // edges, which most of the time will cause an overflow
            // (since technically its outside of the domain).
            int temp = scratches.obtain();
            MOV_REG_TO_REG(fragment.reg, temp);
            SAR(31, temp);
            NOT(temp);
            OR_REG_TO_REG(temp, fragment.reg);
            component_sat(fragment, temp);
            scratches.recycle(temp);
        }
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::decodeLogicOpNeeds(const needs_t& needs)
{
    // gather some informations about the components we need to process...
    const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
    switch(opcode) {
    case GGL_COPY:
        mLogicOp = 0;
        break;
    case GGL_CLEAR:
    case GGL_SET:
        mLogicOp = LOGIC_OP;
        break;
    case GGL_AND:
    case GGL_AND_REVERSE:
    case GGL_AND_INVERTED:
    case GGL_XOR:
    case GGL_OR:
    case GGL_NOR:
    case GGL_EQUIV:
    case GGL_OR_REVERSE:
    case GGL_OR_INVERTED:
    case GGL_NAND:
        mLogicOp = LOGIC_OP|LOGIC_OP_SRC|LOGIC_OP_DST;
        break;
    case GGL_NOOP:
    case GGL_INVERT:
        mLogicOp = LOGIC_OP|LOGIC_OP_DST;
        break;
    case GGL_COPY_INVERTED:
        mLogicOp = LOGIC_OP|LOGIC_OP_SRC;
        break;
    };
}

void GGLX86Assembler::decodeTMUNeeds(const needs_t& needs, context_t const* c)
{
    uint8_t replaced=0;
    mTextureMachine.mask = 0;
    mTextureMachine.activeUnits = 0;
    for (int i=GGL_TEXTURE_UNIT_COUNT-1 ; i>=0 ; i--) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (replaced == 0xF) {
            // all components are replaced, skip this TMU.
            tmu.format_idx = 0;
            tmu.mask = 0;
            tmu.replaced = replaced;
            continue;
        }
        tmu.format_idx = GGL_READ_NEEDS(T_FORMAT, needs.t[i]);
        tmu.format = c->formats[tmu.format_idx];
        tmu.bits = tmu.format.size*8;
        tmu.swrap = GGL_READ_NEEDS(T_S_WRAP, needs.t[i]);
        tmu.twrap = GGL_READ_NEEDS(T_T_WRAP, needs.t[i]);
        tmu.env = ggl_needs_to_env(GGL_READ_NEEDS(T_ENV, needs.t[i]));
        tmu.pot = GGL_READ_NEEDS(T_POT, needs.t[i]);
        tmu.linear = GGL_READ_NEEDS(T_LINEAR, needs.t[i])
                     && tmu.format.size!=3; // XXX: only 8, 16 and 32 modes for now

        // 5551 linear filtering is not supported
        if (tmu.format_idx == GGL_PIXEL_FORMAT_RGBA_5551)
            tmu.linear = 0;

        tmu.mask = 0;
        tmu.replaced = replaced;

        if (tmu.format_idx) {
            mTextureMachine.activeUnits++;
            if (tmu.format.c[0].h)    tmu.mask |= 0x1;
            if (tmu.format.c[1].h)    tmu.mask |= 0x2;
            if (tmu.format.c[2].h)    tmu.mask |= 0x4;
            if (tmu.format.c[3].h)    tmu.mask |= 0x8;
            if (tmu.env == GGL_REPLACE) {
                replaced |= tmu.mask;
            } else if (tmu.env == GGL_DECAL) {
                if (!tmu.format.c[GGLFormat::ALPHA].h) {
                    // if we don't have alpha, decal does nothing
                    tmu.mask = 0;
                } else {
                    // decal always ignores At
                    tmu.mask &= ~(1<<GGLFormat::ALPHA);
                }
            }
        }
        mTextureMachine.mask |= tmu.mask;
        ////printf("%d: mask=%08lx, replaced=%08lx\n",
        //    i, int(tmu.mask), int(tmu.replaced));
    }
    mTextureMachine.replaced = replaced;
    mTextureMachine.directTexture = 0;
    ////printf("replaced=%08lx\n", mTextureMachine.replaced);
}


void GGLX86Assembler::init_textures(
    tex_coord_t* coords,
    const reg_t& x, const reg_t& y)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;
    reg_t temp_reg_t;
    int Rx = x.reg;
    int Ry = y.reg;

    if (mTextureMachine.mask) {
        comment("compute texture coordinates");
    }

    // init texture coordinates for each tmu
    const int cb_format_idx = GGL_READ_NEEDS(CB_FORMAT, needs.n);
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;
        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
                (tmu.twrap == GGL_NEEDS_WRAP_11))
        {
            Scratch scratches(registerFile());
            // 1:1 texture
            pointer_t& txPtr = coords[i].ptr;
            txPtr.setTo(obtainReg(), tmu.bits);
            CONTEXT_LOAD(txPtr.reg, state.texture[i].iterators.ydsdy);
            SAR(16, txPtr.reg);
            ADD_REG_TO_REG(txPtr.reg, Rx);
            CONTEXT_LOAD(txPtr.reg, state.texture[i].iterators.ydtdy);
            SAR(16, txPtr.reg);
            ADD_REG_TO_REG(txPtr.reg, Ry);
            // Rx and Ry are changed
            // Rx = Rx + ti.iterators.ydsdy>>16
            // Ry = Ry + ti.iterators.ydtdy>>16
            // Rx = Ry * ti.stide + Rx

            // merge base & offset
            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].stride);
            IMUL(Ry, txPtr.reg);
            ADD_REG_TO_REG(txPtr.reg, Rx);

            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].data);
            temp_reg_t.setTo(Rx);
            base_offset(txPtr, txPtr, temp_reg_t);
            //PUSH(txPtr.reg);
            mCurSp = mCurSp - 4;
            txPtr.offset_ebp = mCurSp; //ebx, esi, edi, parts.count.reg, parts.cbPtr.reg, parts.z.reg
            MOV_REG_TO_MEM(txPtr.reg, txPtr.offset_ebp, EBP);
            recycleReg(txPtr.reg);
            txPtr.reg=-1;
        } else {
            Scratch scratches(registerFile());
            reg_t& s = coords[i].s;
            reg_t& t = coords[i].t;
            // s = (x * dsdx)>>16 + ydsdy
            // s = (x * dsdx)>>16 + (y*dsdy)>>16 + s0
            // t = (x * dtdx)>>16 + ydtdy
            // t = (x * dtdx)>>16 + (y*dtdy)>>16 + t0
            const int need_w = GGL_READ_NEEDS(W, needs.n);
            MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
            if (need_w) {
                s.setTo(obtainReg());
                t.setTo(obtainReg());
                CONTEXT_LOAD(s.reg, state.texture[i].iterators.ydsdy);
                CONTEXT_LOAD(t.reg, state.texture[i].iterators.ydtdy);
                CONTEXT_STORE(s.reg, generated_vars.texture[i].spill[0]);
                CONTEXT_STORE(t.reg, generated_vars.texture[i].spill[1]);
                recycleReg(s.reg);
                recycleReg(t.reg);
            } else {
                int ydsdy = scratches.obtain();
                int dsdx = scratches.obtain();
                CONTEXT_LOAD(ydsdy, state.texture[i].iterators.ydsdy);
                CONTEXT_LOAD(dsdx, generated_vars.texture[i].dsdx);
                IMUL(Rx, dsdx);
                ADD_REG_TO_REG(dsdx, ydsdy);
                CONTEXT_STORE(ydsdy, generated_vars.texture[i].spill[0]);
                scratches.recycle(ydsdy);
                scratches.recycle(dsdx);

                int ydtdy = scratches.obtain();
                int dtdx = scratches.obtain();
                CONTEXT_LOAD(ydtdy, state.texture[i].iterators.ydtdy);
                CONTEXT_LOAD(dtdx, generated_vars.texture[i].dtdx);
                IMUL(Rx, dtdx);
                ADD_REG_TO_REG(dtdx, ydtdy);
                CONTEXT_STORE(ydtdy, generated_vars.texture[i].spill[1]);
                scratches.recycle(ydtdy);
                scratches.recycle(dtdx);

                // s.reg = Rx * ti.dsdx + ydsdy
                // t.reg = Rx * ti.dtdx + ydtdy
            }
        }

        // direct texture?
        if (!multiTexture && !mBlending && !mDithering && !mFog &&
                cb_format_idx == tmu.format_idx && !tmu.linear &&
                mTextureMachine.replaced == tmu.mask)
        {
            mTextureMachine.directTexture = i + 1;
        }
    }
}

void GGLX86Assembler::build_textures(  fragment_parts_t& parts,
                                       Scratch& regs)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;
    reg_t temp_reg_t;
    //int Rctx = mBuilderContext.Rctx;


    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;

        pointer_t& txPtr = parts.coords[i].ptr;
        pixel_t& texel = parts.texel[i];

        // repeat...
        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
                (tmu.twrap == GGL_NEEDS_WRAP_11))
        {   // 1:1 textures
            comment("fetch texel");
            texel.setTo(regs.obtain(), &tmu.format);
            txPtr.reg = regs.obtain();
            MOV_MEM_TO_REG(txPtr.offset_ebp, EBP, txPtr.reg);
            mCurSp = mCurSp - 4;
            texel.offset_ebp = mCurSp;
            load(txPtr, texel, WRITE_BACK);
            MOV_REG_TO_MEM(texel.reg, texel.offset_ebp, EBP);
            regs.recycle(texel.reg);
            regs.recycle(txPtr.reg);
        } else {
            Scratch scratches(registerFile());
            reg_t& s = parts.coords[i].s;
            reg_t& t = parts.coords[i].t;
            comment("reload s/t (multitexture or linear filtering)");
            s.reg = scratches.obtain();
            t.reg = scratches.obtain();
            mBuilderContext.Rctx = scratches.obtain();
            MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
            CONTEXT_LOAD(s.reg, generated_vars.texture[i].spill[0]);
            CONTEXT_LOAD(t.reg, generated_vars.texture[i].spill[1]);

            comment("compute repeat/clamp");
            int width   = scratches.obtain();
            int height  = scratches.obtain();
            int U = 0;
            int V = 0;
            // U and V will be stored onto the stack due to the limited register
            reg_t reg_U, reg_V;

            CONTEXT_LOAD(width,  generated_vars.texture[i].width);
            CONTEXT_LOAD(height, generated_vars.texture[i].height);
            scratches.recycle(mBuilderContext.Rctx);

            int FRAC_BITS = 0;
            if (tmu.linear) {
                // linear interpolation
                if (tmu.format.size == 1) {
                    // for 8-bits textures, we can afford
                    // 7 bits of fractional precision at no
                    // additional cost (we can't do 8 bits
                    // because filter8 uses signed 16 bits muls)
                    FRAC_BITS = 7;
                } else if (tmu.format.size == 2) {
                    // filter16() is internally limited to 4 bits, so:
                    // FRAC_BITS=2 generates less instructions,
                    // FRAC_BITS=3,4,5 creates unpleasant artifacts,
                    // FRAC_BITS=6+ looks good
                    FRAC_BITS = 6;
                } else if (tmu.format.size == 4) {
                    // filter32() is internally limited to 8 bits, so:
                    // FRAC_BITS=4 looks good
                    // FRAC_BITS=5+ looks better, but generates 3 extra ipp
                    FRAC_BITS = 6;
                } else {
                    // for all other cases we use 4 bits.
                    FRAC_BITS = 4;
                }
            }
            int u       = scratches.obtain();
            // s.reg and t.reg are recycled in wrapping
            wrapping(u, s.reg, width,  tmu.swrap, FRAC_BITS, scratches);
            int v       = scratches.obtain();
            wrapping(v, t.reg, height, tmu.twrap, FRAC_BITS, scratches);


            if (tmu.linear) {

                //mBuilderContext.Rctx = scratches.obtain();
                //MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
                //CONTEXT_LOAD(width,  generated_vars.texture[i].width);
                //CONTEXT_LOAD(height, generated_vars.texture[i].height);
                //scratches.recycle(mBuilderContext.Rctx);

                comment("compute linear filtering offsets");
                // pixel size scale
                const int shift = 31 - gglClz(tmu.format.size);
                U = scratches.obtain();
                V = scratches.obtain();


                // sample the texel center
                SUB_IMM_TO_REG(1<<(FRAC_BITS-1), u);
                SUB_IMM_TO_REG(1<<(FRAC_BITS-1), v);

                // get the fractionnal part of U,V
                MOV_REG_TO_REG(u, U);
                AND_IMM_TO_REG((1<<FRAC_BITS)-1, U);
                MOV_REG_TO_REG(v, V);
                AND_IMM_TO_REG((1<<FRAC_BITS)-1, V);

                // below we will pop U and V in the filter function
                mCurSp = mCurSp - 4;
                MOV_REG_TO_MEM(U, mCurSp, EBP);
                reg_U.offset_ebp = mCurSp;
                mCurSp = mCurSp - 4;
                MOV_REG_TO_MEM(V, mCurSp, EBP);
                reg_V.offset_ebp = mCurSp;

                scratches.recycle(U);
                scratches.recycle(V);

                // compute width-1 and height-1
                SUB_IMM_TO_REG(1, width);
                SUB_IMM_TO_REG(1, height);

                // the registers are used up
                int temp1 = scratches.obtain();
                int temp2 = scratches.obtain();
                // get the integer part of U,V and clamp/wrap
                // and compute offset to the next texel
                if (tmu.swrap == GGL_NEEDS_WRAP_REPEAT) {
                    // u has already been REPEATed
                    SAR(FRAC_BITS, u);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, width, u);
                    MOV_IMM_TO_REG(1<<shift, temp1);
                    MOV_REG_TO_REG(width, temp2);
                    // SHL may pollute the CF flag
                    SHL(shift, temp2);
                    mCurSp = mCurSp - 4;
                    int width_offset_ebp = mCurSp;
                    // width will be changed after the first comparison
                    MOV_REG_TO_MEM(width, width_offset_ebp, EBP);
                    CMP_REG_TO_REG(width, u);
                    CMOV_REG_TO_REG(Mnemonic_CMOVL, temp1, width);
                    if (shift) {
                        CMOV_REG_TO_REG(Mnemonic_CMOVGE, temp2, width);
                    }
                    MOV_REG_TO_REG(width, temp1);
                    NEG(temp1);
                    // width is actually changed
                    CMP_MEM_TO_REG(EBP, width_offset_ebp, u);
                    CMOV_REG_TO_REG(Mnemonic_CMOVGE, temp1, width);
                } else {
                    // u has not been CLAMPed yet
                    // algorithm:
                    // if ((u>>4) >= width)
                    //      u = width<<4
                    //      width = 0
                    // else
                    //      width = 1<<shift
                    // u = u>>4; // get integer part
                    // if (u<0)
                    //      u = 0
                    //      width = 0
                    // generated_vars.rt = width

                    MOV_REG_TO_REG(width, temp2);
                    SHL(FRAC_BITS, temp2);
                    MOV_REG_TO_REG(u, temp1);
                    SAR(FRAC_BITS, temp1);
                    CMP_REG_TO_REG(temp1, width);
                    CMOV_REG_TO_REG(Mnemonic_CMOVLE, temp2, u);
                    // mov doesn't affect the flags
                    MOV_IMM_TO_REG(0, temp2);
                    CMOV_REG_TO_REG(Mnemonic_CMOVLE, temp2, width);
                    MOV_IMM_TO_REG(1 << shift, temp2);
                    CMOV_REG_TO_REG(Mnemonic_CMOVG, temp2, width);

                    MOV_IMM_TO_REG(0, temp2);
                    SAR(FRAC_BITS, u);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, temp2, u);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, temp2, width);
                }
                scratches.recycle(temp1);
                scratches.recycle(temp2);
                mBuilderContext.Rctx = scratches.obtain();
                MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
                CONTEXT_STORE(width, generated_vars.rt);

                const int stride = width;
                CONTEXT_LOAD(stride, generated_vars.texture[i].stride);
                scratches.recycle(mBuilderContext.Rctx);

                temp1 = scratches.obtain();
                temp2 = scratches.obtain();

                int height_offset_ebp;
                if (tmu.twrap == GGL_NEEDS_WRAP_REPEAT) {
                    // v has already been REPEATed
                    SAR(FRAC_BITS, v);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, height, v);
                    MOV_IMM_TO_REG(1<<shift, temp1);
                    MOV_REG_TO_REG(height, temp2);
                    SHL(shift, temp2);
                    mCurSp = mCurSp - 4;
                    height_offset_ebp = mCurSp;
                    // height will be changed after the first comparison
                    MOV_REG_TO_MEM(height, height_offset_ebp, EBP);
                    CMP_REG_TO_REG(height, v);
                    CMOV_REG_TO_REG(Mnemonic_CMOVL, temp1, height);
                    if (shift) {
                        CMOV_REG_TO_REG(Mnemonic_CMOVGE, temp2, height);
                    }
                    MOV_REG_TO_REG(height, temp1);
                    NEG(temp1);
                    // height is actually changed
                    CMP_MEM_TO_REG(EBP, height_offset_ebp, v);
                    CMOV_REG_TO_REG(Mnemonic_CMOVGE, temp1, height);
                    IMUL(stride, height);
                } else {
                    // u has not been CLAMPed yet
                    MOV_REG_TO_REG(height, temp2);
                    SHL(FRAC_BITS, temp2);
                    MOV_REG_TO_REG(v, temp1);
                    SAR(FRAC_BITS, temp1);

                    mCurSp = mCurSp - 4;
                    height_offset_ebp = mCurSp;
                    // height may be changed after the first comparison
                    MOV_REG_TO_MEM(height, height_offset_ebp, EBP);

                    CMP_REG_TO_REG(temp1, height);
                    CMOV_REG_TO_REG(Mnemonic_CMOVLE, temp2, v);
                    MOV_IMM_TO_REG(0, temp2);
                    CMOV_REG_TO_REG(Mnemonic_CMOVLE, temp2, height);

                    if (shift) {
                        // stride = width. It's not used
                        // shift may pollute the flags
                        SHL(shift, stride);
                        // height may be changed to 0
                        CMP_REG_TO_MEM(temp1, height_offset_ebp, EBP);
                        CMOV_REG_TO_REG(Mnemonic_CMOVG, stride, height);
                    } else {
                        CMOV_REG_TO_REG(Mnemonic_CMOVG, stride, height);
                    }
                    MOV_IMM_TO_REG(0, temp2);
                    SAR(FRAC_BITS, v);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, temp2, v);
                    CMOV_REG_TO_REG(Mnemonic_CMOVS, temp2, height);
                }
                scratches.recycle(temp1);
                scratches.recycle(temp2);
                mBuilderContext.Rctx = scratches.obtain();
                MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
                CONTEXT_STORE(height, generated_vars.lb);
                scratches.recycle(mBuilderContext.Rctx);
            }

            scratches.recycle(width);
            scratches.recycle(height);

            // iterate texture coordinates...
            comment("iterate s,t");
            int dsdx = scratches.obtain();
            s.reg = scratches.obtain();
            mBuilderContext.Rctx = scratches.obtain();
            MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
            CONTEXT_LOAD(dsdx, generated_vars.texture[i].dsdx);
            CONTEXT_LOAD(s.reg, generated_vars.texture[i].spill[0]);
            ADD_REG_TO_REG(dsdx, s.reg);
            CONTEXT_STORE(s.reg, generated_vars.texture[i].spill[0]);
            scratches.recycle(s.reg);
            scratches.recycle(dsdx);
            int dtdx = scratches.obtain();
            t.reg = scratches.obtain();
            CONTEXT_LOAD(dtdx, generated_vars.texture[i].dtdx);
            CONTEXT_LOAD(t.reg, generated_vars.texture[i].spill[1]);
            ADD_REG_TO_REG(dtdx, t.reg);
            CONTEXT_STORE(t.reg, generated_vars.texture[i].spill[1]);
            scratches.recycle(dtdx);
            scratches.recycle(t.reg);

            // merge base & offset...
            comment("merge base & offset");
            texel.setTo(scratches.obtain(), &tmu.format);
            //txPtr.setTo(texel.reg, tmu.bits);
            txPtr.setTo(scratches.obtain(), tmu.bits);
            int stride = scratches.obtain();
            CONTEXT_LOAD(stride,    generated_vars.texture[i].stride);
            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].data);
            scratches.recycle(mBuilderContext.Rctx);
            MOVSX_REG_TO_REG(OpndSize_16, v, v);
            MOVSX_REG_TO_REG(OpndSize_16, stride, stride);
            IMUL(v, stride);
            ADD_REG_TO_REG(stride, u);// u+v*stride
            temp_reg_t.setTo(u);
            base_offset(txPtr, txPtr, temp_reg_t);

            // recycle registers we don't need anymore
            scratches.recycle(u);
            scratches.recycle(v);
            scratches.recycle(stride);

            mCurSp = mCurSp - 4;
            texel.offset_ebp = mCurSp;
            // load texel
            if (!tmu.linear) {
                comment("fetch texel in building texture");
                load(txPtr, texel, 0);
                MOV_REG_TO_MEM(texel.reg, texel.offset_ebp, EBP);
                scratches.recycle(texel.reg);
                scratches.recycle(txPtr.reg);
            } else {
                comment("fetch texel, bilinear");
                // the registes are not enough. We spill texel and previous U and V
                // texel.reg is recycled in the following functions since there are more than one code path
                switch (tmu.format.size) {
                case 1:
                    filter8(parts, texel, tmu, reg_U, reg_V, txPtr, FRAC_BITS, scratches);
                    break;
                case 2:
                    filter16(parts, texel, tmu, reg_U, reg_V, txPtr, FRAC_BITS, scratches);
                    break;
                case 3:
                    filter24(parts, texel, tmu, U, V, txPtr, FRAC_BITS);
                    break;
                case 4:
                    filter32(parts, texel, tmu, reg_U, reg_V, txPtr, FRAC_BITS, scratches);
                    break;
                }
            }
        }
    }
}

void GGLX86Assembler::build_iterate_texture_coordinates(
    const fragment_parts_t& parts)
{
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;

        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
                (tmu.twrap == GGL_NEEDS_WRAP_11))
        {   // 1:1 textures
            const pointer_t& txPtr = parts.coords[i].ptr;
            ADD_IMM_TO_MEM(txPtr.size>>3, txPtr.offset_ebp, EBP);
        } else {
            Scratch scratches(registerFile());
            int s = parts.coords[i].s.reg;
            int t = parts.coords[i].t.reg;
            mBuilderContext.Rctx = scratches.obtain();
            MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
            s = scratches.obtain();
            int dsdx = scratches.obtain();
            CONTEXT_LOAD(s, generated_vars.texture[i].spill[0]);
            CONTEXT_LOAD(dsdx, generated_vars.texture[i].dsdx);
            ADD_REG_TO_REG(dsdx, s);
            CONTEXT_STORE(s, generated_vars.texture[i].spill[0]);
            scratches.recycle(s);
            scratches.recycle(dsdx);
            int dtdx = scratches.obtain();
            t = scratches.obtain();
            CONTEXT_LOAD(t, generated_vars.texture[i].spill[1]);
            CONTEXT_LOAD(dtdx, generated_vars.texture[i].dtdx);
            ADD_REG_TO_REG(dtdx, t);
            CONTEXT_STORE(t, generated_vars.texture[i].spill[1]);
            scratches.recycle(t);
            scratches.recycle(dtdx);
        }
    }
}

void GGLX86Assembler::filter8(
    const fragment_parts_t& parts,
    pixel_t& texel, const texture_unit_t& tmu,
    reg_t reg_U, reg_t reg_V, pointer_t& txPtr,
    int FRAC_BITS, Scratch& scratches)
{
    if (tmu.format.components != GGL_ALPHA &&
            tmu.format.components != GGL_LUMINANCE)
    {
        // this is a packed format, and we don't support
        // linear filtering (it's probably RGB 332)
        // Should not happen with OpenGL|ES
        MOVZX_MEM_TO_REG(OpndSize_8, txPtr.reg, 0, texel.reg);
        MOV_REG_TO_MEM(texel.reg, texel.offset_ebp, EBP);
        scratches.recycle(texel.reg);
        scratches.recycle(txPtr.reg);
        return;
    }

    // ------------------------

    //int d    = scratches.obtain();
    //int u    = scratches.obtain();
    //int k    = scratches.obtain();

    scratches.recycle(texel.reg);
    int rt   = scratches.obtain();
    int lb   = scratches.obtain();

    // RB -> U * V

    mBuilderContext.Rctx = scratches.obtain();
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(rt, generated_vars.rt);
    CONTEXT_LOAD(lb, generated_vars.lb);
    scratches.recycle(mBuilderContext.Rctx);
    int pixel= scratches.obtain();

    int offset = pixel;

    MOV_REG_TO_REG(rt, offset);
    ADD_REG_TO_REG(lb, offset);

    int temp_reg1 = scratches.obtain();
    int temp_reg2 = scratches.obtain();
    // it seems that the address mode with base and scale reg cannot be encoded correctly
    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, temp_reg1, OpndSize_8);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOVZX_MEM_TO_REG(OpndSize_8, offset, 0, temp_reg1);
    // pixel is only 8-bits
    MOV_REG_TO_REG(temp_reg1, pixel);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_U.offset_ebp, temp_reg1);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg2);
    IMUL(temp_reg2, temp_reg1);
    MOVSX_REG_TO_REG(OpndSize_16, pixel, pixel);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg1, temp_reg2);
    IMUL(temp_reg2, pixel);
    NEG(temp_reg1);
    ADD_IMM_TO_REG(1<<(FRAC_BITS*2), temp_reg1);
    mCurSp = mCurSp - 4;
    int d_offset_ebp = mCurSp;
    MOV_REG_TO_MEM(pixel, d_offset_ebp, EBP);
    mCurSp = mCurSp - 4;
    int k_offset_ebp = mCurSp;
    MOV_REG_TO_MEM(temp_reg1, k_offset_ebp, EBP);


    // LB -> (1-U) * V
    MOV_MEM_TO_REG(reg_U.offset_ebp, EBP, temp_reg2);
    NEG(temp_reg2);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg2);
    MOV_REG_TO_MEM(temp_reg2, reg_U.offset_ebp, EBP);

    //MOV_MEM_SCALE_TO_REG(txPtr.reg, lb, 1, pixel, OpndSize_8);
    ADD_REG_TO_REG(txPtr.reg, lb);
    MOVZX_MEM_TO_REG(OpndSize_8, lb, 0, pixel);

    MOVSX_REG_TO_REG(OpndSize_16, temp_reg2, temp_reg2);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg1);
    IMUL(temp_reg1, temp_reg2);
    MOVSX_REG_TO_REG(OpndSize_16, pixel, pixel);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg2, temp_reg1);
    IMUL(pixel, temp_reg1);
    ADD_REG_TO_MEM(temp_reg1, EBP, d_offset_ebp);
    SUB_REG_TO_MEM(temp_reg2, EBP, k_offset_ebp);


    // LT -> (1-U)*(1-V)
    MOV_MEM_TO_REG(reg_V.offset_ebp, EBP, temp_reg2);
    NEG(temp_reg2);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg2);
    MOV_REG_TO_MEM(temp_reg2, reg_V.offset_ebp, EBP);

    MOVZX_MEM_TO_REG(OpndSize_8, txPtr.reg, 0, pixel);

    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_U.offset_ebp, temp_reg1);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg2, temp_reg2);
    IMUL(temp_reg1, temp_reg2);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg2, temp_reg1);
    MOVSX_REG_TO_REG(OpndSize_16, pixel, pixel);
    IMUL(pixel, temp_reg1);
    ADD_REG_TO_MEM(temp_reg1, EBP, d_offset_ebp);

    // RT -> U*(1-V)
    //MOV_MEM_SCALE_TO_REG(txPtr.reg, rt, 1, pixel, OpndSize_8);
    ADD_REG_TO_REG(txPtr.reg, rt);
    MOVZX_MEM_TO_REG(OpndSize_8, rt, 0, pixel);

    int k = rt;
    MOV_MEM_TO_REG(k_offset_ebp, EBP, k);
    SUB_REG_TO_REG(temp_reg2, k);
    MOVSX_REG_TO_REG(OpndSize_16, pixel, pixel);
    MOVSX_REG_TO_REG(OpndSize_16, k, k);
    IMUL(pixel, k);
    ADD_MEM_TO_REG(EBP, d_offset_ebp, k);
    MOV_REG_TO_MEM(k, texel.offset_ebp, EBP);
    scratches.recycle(rt);
    scratches.recycle(lb);
    scratches.recycle(pixel);
    scratches.recycle(txPtr.reg);
    scratches.recycle(temp_reg1);
    scratches.recycle(temp_reg2);
    for (int i=0 ; i<4 ; i++) {
        if (!texel.format.c[i].h) continue;
        texel.format.c[i].h = FRAC_BITS*2+8;
        texel.format.c[i].l = FRAC_BITS*2; // keeping 8 bits in enough
    }
    texel.format.size = 4;
    texel.format.bitsPerPixel = 32;
    texel.flags |= CLEAR_LO;
}

void GGLX86Assembler::filter16(
    const fragment_parts_t& parts,
    pixel_t& texel, const texture_unit_t& tmu,
    reg_t reg_U, reg_t reg_V, pointer_t& txPtr,
    int FRAC_BITS, Scratch& scratches)
{
    // compute the mask
    // XXX: it would be nice if the mask below could be computed
    // automatically.
    uint32_t mask = 0;
    int shift = 0;
    int prec = 0;
    switch (tmu.format_idx) {
    case GGL_PIXEL_FORMAT_RGB_565:
        // source: 00000ggg.ggg00000 | rrrrr000.000bbbbb
        // result: gggggggg.gggrrrrr | rrrrr0bb.bbbbbbbb
        mask = 0x07E0F81F;
        shift = 16;
        prec = 5;
        break;
    case GGL_PIXEL_FORMAT_RGBA_4444:
        // 0000,1111,0000,1111 | 0000,1111,0000,1111
        mask = 0x0F0F0F0F;
        shift = 12;
        prec = 4;
        break;
    case GGL_PIXEL_FORMAT_LA_88:
        // 0000,0000,1111,1111 | 0000,0000,1111,1111
        // AALL -> 00AA | 00LL
        mask = 0x00FF00FF;
        shift = 8;
        prec = 8;
        break;
    default:
        // unsupported format, do something sensical...
        ALOGE("Unsupported 16-bits texture format (%d)", tmu.format_idx);
        MOVZX_MEM_TO_REG(OpndSize_16, txPtr.reg, 0, texel.reg);
        MOV_REG_TO_MEM(texel.reg, texel.offset_ebp, EBP);
        scratches.recycle(texel.reg);
        scratches.recycle(txPtr.reg);
        return;
    }

    const int adjust = FRAC_BITS*2 - prec;
    const int round  = 0;

    // update the texel format
    texel.format.size = 4;
    texel.format.bitsPerPixel = 32;
    texel.flags |= CLEAR_HI|CLEAR_LO;
    for (int i=0 ; i<4 ; i++) {
        if (!texel.format.c[i].h) continue;
        const uint32_t offset = (mask & tmu.format.mask(i)) ? 0 : shift;
        texel.format.c[i].h = tmu.format.c[i].h + offset + prec;
        texel.format.c[i].l = texel.format.c[i].h - (tmu.format.bits(i) + prec);
    }

    // ------------------------

    scratches.recycle(texel.reg);

    int pixel= scratches.obtain();
    int u    = scratches.obtain();
    int temp_reg1 = scratches.obtain();

    // RB -> U * V
    //printf("RB ->  U * V \n");
    int offset = pixel;
    mBuilderContext.Rctx = scratches.obtain();
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(offset, generated_vars.rt);
    CONTEXT_LOAD(u, generated_vars.lb);
    ADD_REG_TO_REG(u, offset);

    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, temp_reg1, OpndSize_16);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOVZX_MEM_TO_REG(OpndSize_16, offset, 0, temp_reg1);

    MOV_REG_TO_REG(temp_reg1, pixel);

    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_U.offset_ebp, u);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg1);
    IMUL(temp_reg1, u);
    MOV_REG_TO_REG(pixel, temp_reg1);
    SHL(shift, temp_reg1);
    OR_REG_TO_REG(temp_reg1, pixel);
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), u);
        SHR(adjust, u);
    }
    int d = scratches.obtain();
    MOV_REG_TO_REG(u, d);
    IMUL(pixel, d);
    NEG(u);
    ADD_IMM_TO_REG(1<<prec, u);


    // LB -> (1-U) * V
    //printf("LB -> (1- U) * V \n");
    MOV_MEM_TO_REG(reg_U.offset_ebp, EBP, temp_reg1);
    NEG(temp_reg1);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg1);
    MOV_REG_TO_MEM(temp_reg1, reg_U.offset_ebp, EBP);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg1, temp_reg1);

    CONTEXT_LOAD(offset, generated_vars.lb);
    scratches.recycle(mBuilderContext.Rctx);
    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, pixel, OpndSize_16);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOVZX_MEM_TO_REG(OpndSize_16, offset, 0, pixel);

    int temp_reg2 = scratches.obtain();
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg2);
    IMUL(temp_reg1, temp_reg2);
    MOV_REG_TO_REG(pixel, temp_reg1);
    SHL(shift, temp_reg1);
    OR_REG_TO_REG(temp_reg1, pixel);
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), temp_reg2);
        SHR(adjust, temp_reg2);
    }
    IMUL(temp_reg2, pixel);
    ADD_REG_TO_REG(pixel, d);
    SUB_REG_TO_REG(temp_reg2, u);


    // LT -> (1-U)*(1-V)
    //printf("LT -> (1- U)*(1-V) \n");
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg2);
    NEG(temp_reg2);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg2);
    MOV_REG_TO_MEM(temp_reg2, reg_V.offset_ebp, EBP);
    MOVZX_MEM_TO_REG(OpndSize_16, txPtr.reg, 0, pixel);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_U.offset_ebp, temp_reg1);
    IMUL(temp_reg1, temp_reg2);
    MOV_REG_TO_REG(pixel, temp_reg1);
    SHL(shift, temp_reg1);
    OR_REG_TO_REG(temp_reg1, pixel);
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), temp_reg2);
        SHR(adjust, temp_reg2);
    }
    IMUL(temp_reg2, pixel);
    ADD_REG_TO_REG(pixel, d);


    // RT -> U*(1-V)
    //printf("RT -> U*(1-V) \n");
    SUB_REG_TO_REG(temp_reg2, u);
    mBuilderContext.Rctx = temp_reg2;
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(temp_reg1, generated_vars.rt);
    //MOV_MEM_SCALE_TO_REG(txPtr.reg, temp_reg1, 1, pixel, OpndSize_16);
    ADD_REG_TO_REG(txPtr.reg, temp_reg1);
    MOVZX_MEM_TO_REG(OpndSize_16, temp_reg1, 0, pixel);

    MOV_REG_TO_REG(pixel, temp_reg1);
    SHL(shift, temp_reg1);
    OR_REG_TO_REG(temp_reg1, pixel);
    build_and_immediate(pixel, pixel, mask, 32);
    IMUL(u, pixel);
    ADD_REG_TO_REG(pixel, d);
    MOV_REG_TO_MEM(d, texel.offset_ebp, EBP);
    scratches.recycle(d);
    scratches.recycle(pixel);
    scratches.recycle(u);
    scratches.recycle(txPtr.reg);
    scratches.recycle(temp_reg1);
    scratches.recycle(temp_reg2);
}

void GGLX86Assembler::filter24(
    const fragment_parts_t& parts,
    pixel_t& texel, const texture_unit_t& tmu,
    int U, int V, pointer_t& txPtr,
    int FRAC_BITS)
{
    // not supported yet (currently disabled)
    load(txPtr, texel, 0);
}

void GGLX86Assembler::filter32(
    const fragment_parts_t& parts,
    pixel_t& texel, const texture_unit_t& tmu,
    reg_t reg_U, reg_t reg_V, pointer_t& txPtr,
    int FRAC_BITS, Scratch& scratches)
{
    const int adjust = FRAC_BITS*2 - 8;
    const int round  = 0;

    // ------------------------
    scratches.recycle(texel.reg);
    int mask = scratches.obtain();
    int pixel= scratches.obtain();
    int u    = scratches.obtain();

    //int dh   = scratches.obtain();
    //int k    = scratches.obtain();
    //int temp = scratches.obtain();
    //int dl   = scratches.obtain();

    MOV_IMM_TO_REG(0xFF, mask);
    OR_IMM_TO_REG(0xFF0000, mask);

    // RB -> U * V
    int offset = pixel;
    mBuilderContext.Rctx = scratches.obtain();
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(offset, generated_vars.rt);
    CONTEXT_LOAD(u, generated_vars.lb);
    ADD_REG_TO_REG(u, offset);
    scratches.recycle(mBuilderContext.Rctx);

    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, u);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOV_MEM_TO_REG(0, offset, u);

    MOV_REG_TO_REG(u, pixel);

    int temp_reg1  = scratches.obtain();
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_U.offset_ebp, temp_reg1);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, u);
    IMUL(temp_reg1, u);
    MOV_REG_TO_REG(mask, temp_reg1);
    AND_REG_TO_REG(pixel, temp_reg1);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), u);
        SHR(adjust, u);
    }
    int temp_reg2  = scratches.obtain();
    MOV_REG_TO_REG(temp_reg1, temp_reg2);
    IMUL(u, temp_reg2);
    SHR(8, pixel);
    AND_REG_TO_REG(mask, pixel);
    IMUL(u, pixel);
    NEG(u);
    ADD_IMM_TO_REG(0x100, u);
    mCurSp = mCurSp - 4;
    int dh_offset_ebp = mCurSp;
    MOV_REG_TO_MEM(temp_reg2, dh_offset_ebp, EBP);
    mCurSp = mCurSp - 4;
    int dl_offset_ebp = mCurSp;
    MOV_REG_TO_MEM(pixel, dl_offset_ebp, EBP);

    // LB -> (1-U) * V
    mBuilderContext.Rctx = temp_reg2;
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(offset, generated_vars.lb);
    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, temp_reg2);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOV_MEM_TO_REG(0, offset, temp_reg2);

    MOV_REG_TO_REG(temp_reg2, pixel);
    MOV_MEM_TO_REG(reg_U.offset_ebp, EBP, temp_reg1);
    NEG(temp_reg1);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg1);
    MOV_REG_TO_MEM(temp_reg1, reg_U.offset_ebp, EBP);
    MOVSX_REG_TO_REG(OpndSize_16, temp_reg1, temp_reg1);
    MOVSX_MEM_TO_REG(OpndSize_16, EBP, reg_V.offset_ebp, temp_reg2);
    IMUL(temp_reg2, temp_reg1);
    MOV_REG_TO_REG(mask, temp_reg2);
    AND_REG_TO_REG(pixel, temp_reg2);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), temp_reg1);
        SHR(adjust, temp_reg1);
    }
    // if we use push and pop txPtr.reg later, It will cause the bad locality, since the esp is already been subtracted before the loop.
    // we will spill txPtr.reg due to the limited register
    mCurSp = mCurSp - 4;
    int txPtr_offset_ebp = mCurSp;
    MOV_REG_TO_MEM(txPtr.reg, txPtr_offset_ebp, EBP);
    //PUSH(txPtr.reg);

    int temp_reg3 = txPtr.reg;
    MOV_REG_TO_REG(temp_reg2, temp_reg3);
    IMUL(temp_reg1, temp_reg3);
    ADD_REG_TO_MEM(temp_reg3, EBP, dh_offset_ebp);
    SHR(8, pixel);
    AND_REG_TO_REG(mask, pixel);
    IMUL(temp_reg1, pixel);
    ADD_REG_TO_MEM(pixel, EBP, dl_offset_ebp);
    SUB_REG_TO_REG(temp_reg1, u);


    // LT -> (1-U)*(1-V)
    MOV_MEM_TO_REG(reg_V.offset_ebp, EBP, temp_reg1);
    NEG(temp_reg1);
    ADD_IMM_TO_REG(1<<FRAC_BITS, temp_reg1);
    MOV_REG_TO_MEM(temp_reg1, reg_V.offset_ebp, EBP);
    MOV_MEM_TO_REG(reg_U.offset_ebp, EBP, temp_reg2);

    MOV_MEM_TO_REG(txPtr_offset_ebp, EBP, txPtr.reg);
    //POP(txPtr.reg);

    MOV_MEM_TO_REG(0, txPtr.reg, pixel);
    IMUL(temp_reg2, temp_reg1);
    //we have already saved txPtr.reg
    temp_reg3 = txPtr.reg;
    MOV_REG_TO_REG(pixel, temp_reg3);
    AND_REG_TO_REG(mask, temp_reg3);
    if (adjust) {
        if (round)
            ADD_IMM_TO_REG(1<<(adjust-1), temp_reg1);
        SHR(adjust, temp_reg1);
    }
    IMUL(temp_reg1, temp_reg3);
    ADD_REG_TO_MEM(temp_reg3, EBP, dh_offset_ebp);
    SHR(8, pixel);
    AND_REG_TO_REG(mask, pixel);
    IMUL(temp_reg1, pixel);
    ADD_REG_TO_MEM(pixel, EBP, dl_offset_ebp);

    // RT -> U*(1-V)
    SUB_REG_TO_REG(temp_reg1, u);
    mBuilderContext.Rctx = temp_reg2;
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(offset, generated_vars.rt);

    MOV_MEM_TO_REG(txPtr_offset_ebp, EBP, txPtr.reg);
    //POP(txPtr.reg);

    //MOV_MEM_SCALE_TO_REG(txPtr.reg, offset, 1, temp_reg2);
    ADD_REG_TO_REG(txPtr.reg, offset);
    MOV_MEM_TO_REG(0, offset, temp_reg2);

    MOV_REG_TO_REG(temp_reg2, pixel);
    AND_REG_TO_REG(mask, temp_reg2);
    IMUL(u, temp_reg2);
    ADD_REG_TO_MEM(temp_reg2, EBP, dh_offset_ebp);
    SHR(8, pixel);
    AND_REG_TO_REG(mask, pixel);
    IMUL(u, pixel);
    ADD_REG_TO_MEM(pixel, EBP, dl_offset_ebp);
    MOV_MEM_TO_REG(dh_offset_ebp, EBP, temp_reg1);
    MOV_MEM_TO_REG(dl_offset_ebp, EBP, temp_reg2);
    SHR(8, temp_reg1);
    AND_REG_TO_REG(mask, temp_reg1);
    SHL(8, mask);
    AND_REG_TO_REG(mask, temp_reg2);
    OR_REG_TO_REG(temp_reg1, temp_reg2);
    MOV_REG_TO_MEM(temp_reg2, texel.offset_ebp, EBP);
    scratches.recycle(u);
    scratches.recycle(mask);
    scratches.recycle(pixel);
    scratches.recycle(txPtr.reg);
    scratches.recycle(temp_reg1);
    scratches.recycle(temp_reg2);

}

void GGLX86Assembler::build_texture_environment(
    component_t& fragment,
    fragment_parts_t& parts,
    int component,
    Scratch& regs)
{
    const uint32_t component_mask = 1<<component;
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    Scratch scratches(registerFile());
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; i++) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];

        if (tmu.mask & component_mask) {
            // replace or modulate with this texture
            if ((tmu.replaced & component_mask) == 0) {
                // not replaced by a later tmu...

                pixel_t texel(parts.texel[i]);
                if (multiTexture &&
                        tmu.swrap == GGL_NEEDS_WRAP_11 &&
                        tmu.twrap == GGL_NEEDS_WRAP_11)
                {
                    texel.reg = scratches.obtain();
                    texel.flags |= CORRUPTIBLE;
                    mCurSp = mCurSp - 4;
                    texel.offset_ebp = mCurSp;
                    comment("fetch texel (multitexture 1:1)");
                    parts.coords[i].ptr.reg = scratches.obtain();
                    MOV_MEM_TO_REG(parts.coords[i].ptr.offset_ebp, EBP, parts.coords[i].ptr.reg);
                    load(parts.coords[i].ptr, texel, WRITE_BACK);
                    MOV_REG_TO_MEM(texel.reg, texel.offset_ebp, EBP);
                    scratches.recycle(parts.coords[i].ptr.reg);
                } else {
                    // the texel is already loaded in building textures
                    texel.reg = scratches.obtain();
                    MOV_MEM_TO_REG(texel.offset_ebp, EBP, texel.reg);
                }

                component_t incoming(fragment);
                modify(fragment, regs);

                switch (tmu.env) {
                case GGL_REPLACE:
                    extract(fragment, texel, component);
                    break;
                case GGL_MODULATE:
                    modulate(fragment, incoming, texel, component);
                    break;
                case GGL_DECAL:
                    decal(fragment, incoming, texel, component);
                    break;
                case GGL_BLEND:
                    blend(fragment, incoming, texel, component, i);
                    break;
                case GGL_ADD:
                    add(fragment, incoming, texel, component);
                    break;
                }
                scratches.recycle(texel.reg);
            }
        }
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::wrapping(
    int d,
    int coord, int size,
    int tx_wrap, int tx_linear, Scratch& scratches)
{
    // coord is recycled after return, so it can be written.
    // notes:
    // if tx_linear is set, we need 4 extra bits of precision on the result
    // SMULL/UMULL is 3 cycles
    // coord is actually s.reg or t.reg which will not be used
    int c = coord;
    if (tx_wrap == GGL_NEEDS_WRAP_REPEAT) {
        // UMULL takes 4 cycles (interlocked), and we can get away with
        // 2 cycles using SMULWB, but we're loosing 16 bits of precision
        // out of 32 (this is not a problem because the iterator keeps
        // its full precision)
        // UMULL(AL, 0, size, d, c, size);
        // note: we can't use SMULTB because it's signed.
        MOV_REG_TO_REG(c, d);
        SHR(16-tx_linear, d);
        int temp_reg;
        if(c != EDX)
            temp_reg = c;
        else {
            temp_reg = scratches.obtain();
            scratches.recycle(c);
        }
        int flag_push_edx = -1;
        int flag_reserve_edx = -1;
        int edx_offset_ebp = 0;
        if(scratches.isUsed(EDX) == 1) { //not indicates that the registers are used up. Probably, previous allocated registers are recycled
            if((d != EDX) && (size != EDX)) {
                flag_push_edx = 1;
                mCurSp = mCurSp - 4;
                edx_offset_ebp = mCurSp;
                MOV_REG_TO_MEM(EDX, edx_offset_ebp, EBP);
                //PUSH(EDX);
            }
        }
        else {
            flag_reserve_edx = 1;
            scratches.reserve(EDX);
        }
        if(scratches.isUsed(EAX)) {
            if( size == EAX || d == EAX) {
                // size is actually width and height, which will probably be used after wrapping
                MOV_REG_TO_REG(size, temp_reg);
                MOVSX_REG_TO_REG(OpndSize_16, size, size);
                if(size == EAX)
                    IMUL(d);
                else
                    IMUL(size);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, d);

                MOV_REG_TO_REG(temp_reg, size);
            }
            else {
                if(temp_reg != EAX)
                    MOV_REG_TO_REG(EAX, temp_reg);
                MOV_REG_TO_REG(size, EAX);
                MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                IMUL(d);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, d);
                if(temp_reg != EAX)
                    MOV_REG_TO_REG(temp_reg, EAX);
            }
        }
        else {
            MOV_REG_TO_REG(size, EAX);
            MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
            IMUL(d);
            SHL(16, EDX);
            SHR(16, EAX);
            MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
            MOV_REG_TO_REG(EDX, d);
        }
        if(flag_push_edx == 1) {
            MOV_MEM_TO_REG(edx_offset_ebp, EBP, EDX);
            //POP(EDX);
        }
        if(flag_reserve_edx ==1)
            scratches.recycle(EDX);

        scratches.recycle(temp_reg);
        //IMUL(size, d) will cause segmentation fault with GlobalTime
    } else if (tx_wrap == GGL_NEEDS_WRAP_CLAMP_TO_EDGE) {
        if (tx_linear) {
            // 1 cycle
            MOV_REG_TO_REG(coord, d);
            SAR(16-tx_linear, d);
        } else {
            SAR(16, coord);
            MOV_REG_TO_REG(coord, d);
            SAR(31, coord);
            NOT(coord);
            AND_REG_TO_REG(coord, d);

            MOV_REG_TO_REG(size, coord);
            SUB_IMM_TO_REG(1, coord);

            CMP_REG_TO_REG(size, d);
            CMOV_REG_TO_REG(Mnemonic_CMOVGE, coord, d);

        }
        scratches.recycle(coord);
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::modulate(
    component_t& dest,
    const component_t& incoming,
    const pixel_t& incomingTexel, int component)
{
    Scratch locals(registerFile());
    integer_t texel(locals.obtain(), 32, CORRUPTIBLE);
    extract(texel, incomingTexel, component);

    const int Nt = texel.size();
    // Nt should always be less than 10 bits because it comes
    // from the TMU.

    int Ni = incoming.size();
    // Ni could be big because it comes from previous MODULATEs

    if (Nt == 1) {
        // texel acts as a bit-mask
        // dest = incoming & ((texel << incoming.h)-texel)
        MOV_REG_TO_REG(texel.reg, dest.reg);
        SHL(incoming.h, dest.reg);
        SUB_REG_TO_REG(texel.reg, dest.reg);
        dest.l = incoming.l;
        dest.h = incoming.h;
        dest.flags |= (incoming.flags & CLEAR_LO);
    } else if (Ni == 1) {
        SHL(31-incoming.h, incoming.reg);
        MOV_REG_TO_REG(incoming.reg, dest.reg);
        SAR(31, dest.reg);
        AND_REG_TO_REG(texel.reg, dest.reg);
        dest.l = 0;
        dest.h = Nt;
    } else {
        int inReg = incoming.reg;
        int shift = incoming.l;
        if ((Nt + Ni) > 32) {
            // we will overflow, reduce the precision of Ni to 8 bits
            // (Note Nt cannot be more than 10 bits which happens with
            // 565 textures and GGL_LINEAR)
            shift += Ni-8;
            Ni = 8;
        }

        // modulate by the component with the lowest precision
        if (Nt >= Ni) {
            if (shift) {
                // XXX: we should be able to avoid this shift
                // when shift==16 && Nt<16 && Ni<16, in which
                // we could use SMULBT below.
                MOV_REG_TO_REG(inReg, dest.reg);
                SHR(shift, inReg);
                inReg = dest.reg;
                shift = 0;
            }
            int temp_reg = locals.obtain();
            // operation:           (Cf*Ct)/((1<<Ni)-1)
            // approximated with:   Cf*(Ct + Ct>>(Ni-1))>>Ni
            // this operation doesn't change texel's size
            MOV_REG_TO_REG(inReg, temp_reg);
            SHR(Ni-1, temp_reg);
            MOV_REG_TO_REG(inReg, dest.reg);
            ADD_REG_TO_REG(temp_reg, dest.reg);
            locals.recycle(temp_reg);
            if (Nt<16 && Ni<16) {
                MOVSX_REG_TO_REG(OpndSize_16, texel.reg, texel.reg);
                MOVSX_REG_TO_REG(OpndSize_16, dest.reg, dest.reg);
                IMUL(texel.reg, dest.reg);
            }
            else
                IMUL(texel.reg, dest.reg);
            dest.l = Ni;
            dest.h = Nt + Ni;
        } else {
            if (shift && (shift != 16)) {
                // if shift==16, we can use 16-bits mul instructions later
                MOV_REG_TO_REG(inReg, dest.reg);
                SHR(shift, dest.reg);
                inReg = dest.reg;
                shift = 0;
            }
            // operation:           (Cf*Ct)/((1<<Nt)-1)
            // approximated with:   Ct*(Cf + Cf>>(Nt-1))>>Nt
            // this operation doesn't change incoming's size
            Scratch scratches(registerFile());
            int temp_reg = locals.obtain();
            int t = (texel.flags & CORRUPTIBLE) ? texel.reg : dest.reg;
            if (t == inReg)
                t = scratches.obtain();

            MOV_REG_TO_REG(texel.reg, temp_reg);
            SHR(Nt-1, temp_reg);
            ADD_REG_TO_REG(temp_reg, texel.reg);
            MOV_REG_TO_REG(texel.reg, t);
            locals.recycle(temp_reg);
            MOV_REG_TO_REG(inReg, dest.reg);
            if (Nt<16 && Ni<16) {
                if (shift==16) {
                    MOVSX_REG_TO_REG(OpndSize_16, t, t);
                    SHR(16, dest.reg);
                    MOVSX_REG_TO_REG(OpndSize_16, dest.reg, dest.reg);
                    IMUL(t, dest.reg);
                }
                else {
                    MOVSX_REG_TO_REG(OpndSize_16, dest.reg, dest.reg);
                    MOVSX_REG_TO_REG(OpndSize_16, t, t);
                    IMUL(t, dest.reg);
                }
            } else
                IMUL(t, dest.reg);
            dest.l = Nt;
            dest.h = Nt + Ni;
        }

        // low bits are not valid
        dest.flags |= CLEAR_LO;

        // no need to keep more than 8 bits/component
        if (dest.size() > 8)
            dest.l = dest.h-8;
    }
}

void GGLX86Assembler::decal(
    component_t& dest,
    const component_t& incoming,
    const pixel_t& incomingTexel, int component)
{
    // RGBA:
    // Cv = Cf*(1 - At) + Ct*At = Cf + (Ct - Cf)*At
    // Av = Af
    Scratch locals(registerFile());
    integer_t texel(locals.obtain(), 32, CORRUPTIBLE);
    integer_t factor(locals.obtain(), 32, CORRUPTIBLE);
    extract(texel, incomingTexel, component);
    extract(factor, incomingTexel, GGLFormat::ALPHA);

    // no need to keep more than 8-bits for decal
    int Ni = incoming.size();
    int shift = incoming.l;
    if (Ni > 8) {
        shift += Ni-8;
        Ni = 8;
    }
    integer_t incomingNorm(incoming.reg, Ni, incoming.flags);
    if (shift) {
        SHR(shift, incomingNorm.reg);
        MOV_REG_TO_REG(incomingNorm.reg, dest.reg);
        incomingNorm.reg = dest.reg;
        incomingNorm.flags |= CORRUPTIBLE;
    }
    int temp = locals.obtain();
    MOV_REG_TO_REG(factor.reg, temp);
    SHR(factor.s-1, temp);
    ADD_REG_TO_REG(temp, factor.reg);
    locals.recycle(temp);
    build_blendOneMinusFF(dest, factor, incomingNorm, texel);
}

void GGLX86Assembler::blend(
    component_t& dest,
    const component_t& incoming,
    const pixel_t& incomingTexel, int component, int tmu)
{
    // RGBA:
    // Cv = (1 - Ct)*Cf + Ct*Cc = Cf + (Cc - Cf)*Ct
    // Av = At*Af

    if (component == GGLFormat::ALPHA) {
        modulate(dest, incoming, incomingTexel, component);
        return;
    }

    Scratch locals(registerFile());
    int temp = locals.obtain();
    integer_t color(locals.obtain(), 8, CORRUPTIBLE);
    integer_t factor(locals.obtain(), 32, CORRUPTIBLE);
    mBuilderContext.Rctx = temp;
    MOV_MEM_TO_REG(8, PhysicalReg_EBP, mBuilderContext.Rctx);
    MOVZX_MEM_TO_REG(OpndSize_8, mBuilderContext.Rctx, GGL_OFFSETOF(state.texture[tmu].env_color[component]), color.reg);
    extract(factor, incomingTexel, component);

    // no need to keep more than 8-bits for blend
    int Ni = incoming.size();
    int shift = incoming.l;
    if (Ni > 8) {
        shift += Ni-8;
        Ni = 8;
    }
    integer_t incomingNorm(incoming.reg, Ni, incoming.flags);
    if (shift) {
        MOV_REG_TO_REG(incomingNorm.reg, dest.reg);
        SHR(shift, dest.reg);
        incomingNorm.reg = dest.reg;
        incomingNorm.flags |= CORRUPTIBLE;
    }
    MOV_REG_TO_REG(factor.reg, temp);
    SHR(factor.s-1, temp);
    ADD_REG_TO_REG(temp, factor.reg);
    locals.recycle(temp);
    build_blendOneMinusFF(dest, factor, incomingNorm, color);
}

void GGLX86Assembler::add(
    component_t& dest,
    const component_t& incoming,
    const pixel_t& incomingTexel, int component)
{
    // RGBA:
    // Cv = Cf + Ct;
    Scratch locals(registerFile());

    component_t incomingTemp(incoming);

    // use "dest" as a temporary for extracting the texel, unless "dest"
    // overlaps "incoming".
    integer_t texel(dest.reg, 32, CORRUPTIBLE);
    if (dest.reg == incomingTemp.reg)
        texel.reg = locals.obtain();
    extract(texel, incomingTexel, component);

    if (texel.s < incomingTemp.size()) {
        expand(texel, texel, incomingTemp.size());
    } else if (texel.s > incomingTemp.size()) {
        if (incomingTemp.flags & CORRUPTIBLE) {
            expand(incomingTemp, incomingTemp, texel.s);
        } else {
            incomingTemp.reg = locals.obtain();
            expand(incomingTemp, incoming, texel.s);
        }
    }

    if (incomingTemp.l) {
        MOV_REG_TO_REG(incomingTemp.reg, dest.reg);
        SHR(incomingTemp.l, dest.reg);
        ADD_REG_TO_REG(texel.reg, dest.reg);
    } else {
        MOV_REG_TO_REG(incomingTemp.reg, dest.reg);
        ADD_REG_TO_REG(texel.reg, dest.reg);
    }
    dest.l = 0;
    dest.h = texel.size();
    int temp_reg = locals.obtain();
    component_sat(dest, temp_reg);
    locals.recycle(temp_reg);
}

// ----------------------------------------------------------------------------

}; // namespace android
