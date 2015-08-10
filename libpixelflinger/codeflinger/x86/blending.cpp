/* libs/pixelflinger/codeflinger/x86/blending.cpp
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

void GGLX86Assembler::build_fog(
    component_t& temp,      // incomming fragment / output
    int component,
    Scratch& regs)
{
    if (mInfo[component].fog) {
        Scratch scratches(registerFile());
        comment("fog");

        temp.reg = scratches.obtain();
        MOV_MEM_TO_REG(temp.offset_ebp, EBP, temp.reg);
        integer_t fragment(temp.reg, temp.h, temp.flags, temp.offset_ebp);
        if (!(temp.flags & CORRUPTIBLE)) {
            temp.reg = regs.obtain();
            temp.flags |= CORRUPTIBLE;
        }

        integer_t fogColor(scratches.obtain(), 8, CORRUPTIBLE);
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        MOVZX_MEM_TO_REG(OpndSize_8, mBuilderContext.Rctx, GGL_OFFSETOF(state.fog.color[component]), fogColor.reg);

        integer_t factor(scratches.obtain(), 16, CORRUPTIBLE);
        CONTEXT_LOAD(factor.reg, generated_vars.f);
        scratches.recycle(mBuilderContext.Rctx);

        // clamp fog factor (TODO: see if there is a way to guarantee
        // we won't overflow, when setting the iterators)
        int temp_reg = scratches.obtain();
        MOV_REG_TO_REG(factor.reg, temp_reg);
        SAR(31, temp_reg);
        NOT(temp_reg);
        AND_REG_TO_REG(temp_reg, factor.reg);
        MOV_IMM_TO_REG(0x10000, temp_reg);
        CMP_IMM_TO_REG(0x10000, factor.reg);
        CMOV_REG_TO_REG(Mnemonic_CMOVAE, temp_reg, factor.reg);
        scratches.recycle(temp_reg);

        //we will resue factor.reg
        build_blendFOneMinusF(temp, factor, fragment, fogColor);
        MOV_REG_TO_MEM(temp.reg, temp.offset_ebp, EBP);
        scratches.recycle(temp.reg);
    }
}

void GGLX86Assembler::build_blending(
    component_t& temp,      // incomming fragment / output
    pixel_t& pixel,   // framebuffer
    int component,
    Scratch& regs)
{
    if (!mInfo[component].blend)
        return;

    int fs = component==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
    int fd = component==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
    if (fs==GGL_SRC_ALPHA_SATURATE && component==GGLFormat::ALPHA)
        fs = GGL_ONE;
    const int blending = blending_codes(fs, fd);
    if (!temp.size()) {
        // here, blending will produce something which doesn't depend on
        // that component (eg: GL_ZERO:GL_*), so the register has not been
        // allocated yet. Will never be used as a source.
        //temp = component_t(regs.obtain(), CORRUPTIBLE, temp_offset_ebp);
        temp.reg = regs.obtain();
        temp.flags = CORRUPTIBLE;
        temp.h = temp.l = 0;
    } else {
        temp.reg = regs.obtain();
    }
    MOV_MEM_TO_REG(temp.offset_ebp, EBP, temp.reg);
    // we are doing real blending...
    // fb:          extracted dst
    // fragment:    extracted src
    // temp:        component_t(fragment) and result

    // scoped register allocator
    Scratch scratches(registerFile());
    comment("blending");

    // we can optimize these cases a bit...
    // (1) saturation is not needed
    // (2) we can use only one multiply instead of 2
    // (3) we can reduce the register pressure
    //      R = S*f + D*(1-f) = (S-D)*f + D
    //      R = S*(1-f) + D*f = (D-S)*f + S

    const bool same_factor_opt1 =
        (fs==GGL_DST_COLOR && fd==GGL_ONE_MINUS_DST_COLOR) ||
        (fs==GGL_SRC_COLOR && fd==GGL_ONE_MINUS_SRC_COLOR) ||
        (fs==GGL_DST_ALPHA && fd==GGL_ONE_MINUS_DST_ALPHA) ||
        (fs==GGL_SRC_ALPHA && fd==GGL_ONE_MINUS_SRC_ALPHA);

    const bool same_factor_opt2 =
        (fs==GGL_ONE_MINUS_DST_COLOR && fd==GGL_DST_COLOR) ||
        (fs==GGL_ONE_MINUS_SRC_COLOR && fd==GGL_SRC_COLOR) ||
        (fs==GGL_ONE_MINUS_DST_ALPHA && fd==GGL_DST_ALPHA) ||
        (fs==GGL_ONE_MINUS_SRC_ALPHA && fd==GGL_SRC_ALPHA);


    // XXX: we could also optimize these cases:
    // R = S*f + D*f = (S+D)*f
    // R = S*(1-f) + D*(1-f) = (S+D)*(1-f)
    // R = S*D + D*S = 2*S*D


    pixel.reg = scratches.obtain();
    MOV_MEM_TO_REG(pixel.offset_ebp, EBP, pixel.reg);
    // see if we need to extract 'component' from the destination (fb)
    integer_t fb;
    if (blending & (BLEND_DST|FACTOR_DST)) {
        fb.setTo(scratches.obtain(), 32);
        extract(fb, pixel, component);
        if (mDithering) {
            // XXX: maybe what we should do instead, is simply
            // expand fb -or- fragment to the larger of the two
            if (fb.size() < temp.size()) {
                // for now we expand 'fb' to min(fragment, 8)
                int new_size = temp.size() < 8 ? temp.size() : 8;
                expand(fb, fb, new_size);
            }
        }
    }

    // convert input fragment to integer_t
    if (temp.l && (temp.flags & CORRUPTIBLE)) {
        SHR(temp.l, temp.reg);
        temp.h -= temp.l;
        temp.l = 0;
    }
    integer_t fragment(temp.reg, temp.size(), temp.flags, temp.offset_ebp);

    // if not done yet, convert input fragment to integer_t
    if (temp.l) {
        // here we know temp is not CORRUPTIBLE
        fragment.reg = scratches.obtain();
        MOV_REG_TO_REG(temp.reg, fragment.reg);
        SHR(temp.l, fragment.reg);
        fragment.flags |= CORRUPTIBLE;
    }

    if (!(temp.flags & CORRUPTIBLE)) {
        // temp is not corruptible, but since it's the destination it
        // will be modified, so we need to allocate a new register.
        temp.reg = regs.obtain();
        temp.flags &= ~CORRUPTIBLE;
        fragment.flags &= ~CORRUPTIBLE;
    }

    if ((blending & BLEND_SRC) && !same_factor_opt1) {
        // source (fragment) is needed for the blending stage
        // so it's not CORRUPTIBLE (unless we're doing same_factor_opt1)
        fragment.flags &= ~CORRUPTIBLE;
    }


    if (same_factor_opt1) {
        //  R = S*f + D*(1-f) = (S-D)*f + D
        integer_t factor;
        build_blend_factor(factor, fs,
                           component, pixel, fragment, fb, scratches);
        // fb is always corruptible from this point
        fb.flags |= CORRUPTIBLE;
        //we will reuse factor in mul_factor_add of build_blendFOneMinusF, unless factor.reg == fragment.reg == temp.reg or factor.reg == fb.reg in build_blend_factor
        if(factor.reg == fragment.reg || factor.reg == fb.reg)
            MOV_REG_TO_REG(factor.reg, pixel.reg);
        else
            scratches.recycle(pixel.reg);
        build_blendFOneMinusF(temp, factor, fragment, fb);
        if(factor.reg == fragment.reg || factor.reg == fb.reg) {
            MOV_REG_TO_REG(pixel.reg, factor.reg);
            scratches.recycle(pixel.reg);
        }
        scratches.recycle(fb.reg);
        //scratches.recycle(factor.reg);
    } else if (same_factor_opt2) {
        //  R = S*(1-f) + D*f = (D-S)*f + S
        integer_t factor;
        // fb is always corrruptible here
        fb.flags |= CORRUPTIBLE;
        build_blend_factor(factor, fd,
                           component, pixel, fragment, fb, scratches);
        //we will reuse factor in mul_factor_add of build_blendFOneMinusFF, unless factor.reg == fragment.reg == temp.reg or factor.reg == fb.reg in build_blend_factor
        if(factor.reg == fragment.reg || factor.reg == fb.reg)
            MOV_REG_TO_REG(factor.reg, pixel.reg);
        else
            scratches.recycle(pixel.reg);
        build_blendOneMinusFF(temp, factor, fragment, fb);
        if(factor.reg == fragment.reg || factor.reg == fb.reg) {
            MOV_REG_TO_REG(pixel.reg, factor.reg);
            scratches.recycle(pixel.reg);
        }
        scratches.recycle(fb.reg);
    } else {
        integer_t src_factor;
        integer_t dst_factor;

        // if destination (fb) is not needed for the blending stage,
        // then it can be marked as CORRUPTIBLE
        if (!(blending & BLEND_DST)) {
            fb.flags |= CORRUPTIBLE;
        }

        // XXX: try to mark some registers as CORRUPTIBLE
        // in most case we could make those corruptible
        // when we're processing the last component
        // but not always, for instance
        //    when fragment is constant and not reloaded
        //    when fb is needed for logic-ops or masking
        //    when a register is aliased (for instance with mAlphaSource)

        // blend away...
        if (fs==GGL_ZERO) {
            if (fd==GGL_ZERO) {         // R = 0
                // already taken care of
            } else if (fd==GGL_ONE) {   // R = D
                // already taken care of
            } else {                    // R = D*fd
                // compute fd
                build_blend_factor(dst_factor, fd,
                                   component, pixel, fragment, fb, scratches);
                scratches.recycle(pixel.reg);
                mul_factor(temp, fb, dst_factor, regs);
                scratches.recycle(fb.reg);
            }
        } else if (fs==GGL_ONE) {
            int temp_reg;
            if (fd==GGL_ZERO) {     // R = S
                // NOP, taken care of
            } else if (fd==GGL_ONE) {   // R = S + D
                component_add(temp, fb, fragment); // args order matters
                temp_reg = scratches.obtain();
                component_sat(temp, temp_reg);
                scratches.recycle(temp_reg);
            } else {                    // R = S + D*fd
                // compute fd
                build_blend_factor(dst_factor, fd,
                                   component, pixel, fragment, fb, scratches);
                //we will probably change src_factor in mul_factor_add, unless factor.reg == fragment.reg == temp.reg or factor.reg == fb.reg in build_blend_factor
                if(dst_factor.reg == fragment.reg || dst_factor.reg == fb.reg)
                    MOV_REG_TO_REG(dst_factor.reg, pixel.reg);
                else
                    scratches.recycle(pixel.reg);
                mul_factor_add(temp, fb, dst_factor, component_t(fragment));
                if(dst_factor.reg == fragment.reg || dst_factor.reg == fb.reg) {
                    MOV_REG_TO_REG(pixel.reg, dst_factor.reg);
                    scratches.recycle(pixel.reg);
                }
                temp_reg = fb.reg;
                component_sat(temp, temp_reg);
                scratches.recycle(fb.reg);
            }
        } else {
            // compute fs
            int temp_reg;
            build_blend_factor(src_factor, fs,
                               component, pixel, fragment, fb, scratches);
            if (fd==GGL_ZERO) {         // R = S*fs
                mul_factor(temp, fragment, src_factor, regs);
                if (scratches.isUsed(src_factor.reg))
                    scratches.recycle(src_factor.reg);
            } else if (fd==GGL_ONE) {   // R = S*fs + D
                //we will probably change src_factor in mul_factor_add, unless factor.reg == fragment.reg == temp.reg or factor.reg == fb.reg in build_blend_factor
                if(src_factor.reg == fragment.reg || src_factor.reg == fb.reg)
                    MOV_REG_TO_REG(src_factor.reg, pixel.reg);
                else
                    scratches.recycle(pixel.reg);
                mul_factor_add(temp, fragment, src_factor, component_t(fb));
                if(src_factor.reg == fragment.reg || src_factor.reg == fb.reg) {
                    MOV_REG_TO_REG(pixel.reg, src_factor.reg);
                    scratches.recycle(pixel.reg);
                }
                temp_reg = fb.reg;
                component_sat(temp, temp_reg);
                scratches.recycle(fb.reg);
            } else {                    // R = S*fs + D*fd
                mul_factor(temp, fragment, src_factor, regs);
                if (scratches.isUsed(src_factor.reg))
                    scratches.recycle(src_factor.reg);
                // compute fd
                build_blend_factor(dst_factor, fd,
                                   component, pixel, fragment, fb, scratches);
                //we will probably change dst_factor in mul_factor_add, unless factor.reg == fragment.reg == temp.reg or factor.reg == fb.reg
                if(dst_factor.reg == fragment.reg || dst_factor.reg == fb.reg)
                    MOV_REG_TO_REG(dst_factor.reg, pixel.reg);
                else
                    scratches.recycle(pixel.reg);
                mul_factor_add(temp, fb, dst_factor, temp);
                if(dst_factor.reg == fragment.reg || dst_factor.reg == fb.reg) {
                    MOV_REG_TO_REG(pixel.reg, dst_factor.reg);
                    scratches.recycle(pixel.reg);
                }
                if (!same_factor_opt1 && !same_factor_opt2) {
                    temp_reg = fb.reg;
                    component_sat(temp, temp_reg);
                }
                scratches.recycle(fb.reg);
            }
            if(scratches.isUsed(pixel.reg))
                scratches.recycle(pixel.reg);
        }
    }
    // temp is modified, but it will be used immediately in downshift
    //printf("temp.offset_ebp: %d \n", temp.offset_ebp);
    //below will be triggered on CDK for surfaceflinger
    if(temp.offset_ebp == mAlphaSource.offset_ebp) {
        mCurSp = mCurSp - 4;
        temp.offset_ebp = mCurSp;
    }
    // the r, g, b value must be stored, otherwise the color of globaltime is incorrect.
    MOV_REG_TO_MEM(temp.reg, temp.offset_ebp, EBP);
    regs.recycle(temp.reg);

    // now we can be corrupted (it's the dest)
    temp.flags |= CORRUPTIBLE;
}

void GGLX86Assembler::build_blend_factor(
    integer_t& factor, int f, int component,
    const pixel_t& dst_pixel,
    integer_t& fragment,
    integer_t& fb,
    Scratch& scratches)
{
    integer_t src_alpha(fragment);

    // src_factor/dst_factor won't be used after blending,
    // so it's fine to mark them as CORRUPTIBLE (if not aliased)
    factor.flags |= CORRUPTIBLE;
    int temp_reg;
    switch(f) {
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        if (component==GGLFormat::ALPHA && !isAlphaSourceNeeded()) {
            // we're processing alpha, so we already have
            // src-alpha in fragment, and we need src-alpha just this time.
        } else {
            // alpha-src will be needed for other components
            factor = mAlphaSource;
            factor.flags &= ~CORRUPTIBLE;
            factor.reg = scratches.obtain();
            //printf("mAlphaSource.offset_ebp: %d \n", mAlphaSource.offset_ebp);
            //printf("fragment.offset_ebp: %d \n", fragment.offset_ebp);
            //printf("factor.offset_ebp: %d \n", factor.offset_ebp);
            MOV_MEM_TO_REG(mAlphaSource.offset_ebp, EBP, factor.reg);
            if (!mBlendFactorCached || mBlendFactorCached==f) {
                src_alpha = mAlphaSource;
                // we already computed the blend factor before, nothing to do.
                if (mBlendFactorCached)
                    return;
                // this is the first time, make sure to compute the blend
                // factor properly.
                mBlendFactorCached = f;
                break;
            } else {
                // we have a cached alpha blend factor, but we want another one,
                // this should really not happen because by construction,
                // we cannot have BOTH source and destination
                // blend factors use ALPHA *and* ONE_MINUS_ALPHA (because
                // the blending stage uses the f/(1-f) optimization

                // for completeness, we handle this case though. Since there
                // are only 2 choices, this meens we want "the other one"
                // (1-factor)
                //factor = mAlphaSource;
                //factor.flags &= ~CORRUPTIBLE;
                NEG(factor.reg);
                ADD_IMM_TO_REG((1<<factor.s), factor.reg);
                MOV_REG_TO_MEM(factor.reg, factor.offset_ebp, EBP);
                mBlendFactorCached = f;
                return;
            }
        }
        // fall-through...
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
    case GGL_SRC_ALPHA_SATURATE:
        // help us find out what register we can use for the blend-factor
        // CORRUPTIBLE registers are chosen first, or a new one is allocated.
        if (fragment.flags & CORRUPTIBLE) {
            factor.setTo(fragment.reg, 32, CORRUPTIBLE, fragment.offset_ebp);
            fragment.flags &= ~CORRUPTIBLE;
        } else if (fb.flags & CORRUPTIBLE) {
            factor.setTo(fb.reg, 32, CORRUPTIBLE, fb.offset_ebp);
            fb.flags &= ~CORRUPTIBLE;
        } else {
            factor.setTo(scratches.obtain(), 32, CORRUPTIBLE);
            mCurSp = mCurSp - 4;
            factor.offset_ebp = mCurSp;
        }
        break;
    }

    // XXX: doesn't work if size==1

    switch(f) {
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        factor.s = fb.s;
        MOV_REG_TO_REG(fb.reg, factor.reg);
        SHR(fb.s-1, factor.reg);
        ADD_REG_TO_REG(fb.reg, factor.reg);
        break;
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
        factor.s = fragment.s;
        temp_reg = scratches.obtain();
        MOV_REG_TO_REG(fragment.reg, temp_reg);
        SHR(fragment.s-1, fragment.reg);
        ADD_REG_TO_REG(temp_reg, fragment.reg);
        scratches.recycle(temp_reg);
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        factor.s = src_alpha.s;
        if (mBlendFactorCached == f) {
            //src_alpha == factor == mAlphaSource, we need a temp reg
            if(scratches.countFreeRegs()) {
                temp_reg = scratches.obtain();
                MOV_REG_TO_REG(factor.reg, temp_reg);
                SHR(src_alpha.s-1, factor.reg);
                ADD_REG_TO_REG(temp_reg, factor.reg);
                scratches.recycle(temp_reg);
            }
            else {
                SHR(src_alpha.s-1, factor.offset_ebp, EBP);
                ADD_MEM_TO_REG(EBP, factor.offset_ebp, factor.reg);
            }
        }
        else
        {
            MOV_REG_TO_REG(src_alpha.reg, factor.reg);
            SHR(src_alpha.s-1, factor.reg);
            ADD_REG_TO_REG(src_alpha.reg, factor.reg);
        }
        // we will store factor in the next switch for GGL_ONE_MINUS_SRC_ALPHA
        if(f == GGL_SRC_ALPHA)
            MOV_REG_TO_MEM(factor.reg, factor.offset_ebp, EBP);
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        // XXX: should be precomputed
        extract(factor, dst_pixel, GGLFormat::ALPHA);
        temp_reg = scratches.obtain();
        MOV_REG_TO_REG(factor.reg, temp_reg);
        SHR(factor.s-1, factor.reg);
        ADD_REG_TO_REG(temp_reg, factor.reg);
        scratches.recycle(temp_reg);
        break;
    case GGL_SRC_ALPHA_SATURATE:
        // XXX: should be precomputed
        // XXX: f = min(As, 1-Ad)
        // btw, we're guaranteed that Ad's size is <= 8, because
        // it's extracted from the framebuffer
        break;
    }

    switch(f) {
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_ONE_MINUS_SRC_ALPHA:
        NEG(factor.reg);
        ADD_IMM_TO_REG(1<<factor.s, factor.reg);
        MOV_REG_TO_MEM(factor.reg, factor.offset_ebp, EBP);
    }

    // don't need more than 8-bits for the blend factor
    // and this will prevent overflows in the multiplies later
    if (factor.s > 8) {
        SHR(factor.s-8, factor.reg);
        factor.s = 8;
        if(f == GGL_ONE_MINUS_SRC_ALPHA || f == GGL_SRC_ALPHA)
            MOV_REG_TO_MEM(factor.reg, factor.offset_ebp, EBP);
    }
    //below will be triggered on CDK for surfaceflinger
    if(fragment.offset_ebp == mAlphaSource.offset_ebp)
        MOV_REG_TO_REG(factor.reg, fragment.reg);
}

int GGLX86Assembler::blending_codes(int fs, int fd)
{
    int blending = 0;
    switch(fs) {
    case GGL_ONE:
        blending |= BLEND_SRC;
        break;

    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        blending |= FACTOR_DST|BLEND_SRC;
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        // no need to extract 'component' from the destination
        // for the blend factor, because we need ALPHA only.
        blending |= BLEND_SRC;
        break;

    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
        blending |= FACTOR_SRC|BLEND_SRC;
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
    case GGL_SRC_ALPHA_SATURATE:
        blending |= FACTOR_SRC|BLEND_SRC;
        break;
    }
    switch(fd) {
    case GGL_ONE:
        blending |= BLEND_DST;
        break;

    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        blending |= FACTOR_DST|BLEND_DST;
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        blending |= FACTOR_DST|BLEND_DST;
        break;

    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
        blending |= FACTOR_SRC|BLEND_DST;
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        // no need to extract 'component' from the source
        // for the blend factor, because we need ALPHA only.
        blending |= BLEND_DST;
        break;
    }
    return blending;
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_blendFOneMinusF(
    component_t& temp,
    const integer_t& factor,
    const integer_t& fragment,
    const integer_t& fb)
{
    //  R = S*f + D*(1-f) = (S-D)*f + D
    // compute S-D
    Scratch scratches(registerFile());
    integer_t diff(fragment.flags & CORRUPTIBLE ?
                   fragment.reg : scratches.obtain(), fb.size(), CORRUPTIBLE);
    const int shift = fragment.size() - fb.size();
    if (shift>0) {
        MOV_REG_TO_REG(fragment.reg, diff.reg);
        SHR(shift, diff.reg);
        SUB_REG_TO_REG(fb.reg, diff.reg);
    } else if (shift<0) {
        MOV_REG_TO_REG(fragment.reg, diff.reg);
        SHL(-shift, diff.reg);
        SUB_REG_TO_REG(fb.reg, diff.reg);
    } else  {
        MOV_REG_TO_REG(fragment.reg, diff.reg);
        SUB_REG_TO_REG(fb.reg, diff.reg);
    }
    mul_factor_add(temp, diff, factor, component_t(fb));
    if(!(fragment.flags & CORRUPTIBLE))
        scratches.recycle(diff.reg);
}

void GGLX86Assembler::build_blendOneMinusFF(
    component_t& temp,
    const integer_t& factor,
    const integer_t& fragment,
    const integer_t& fb)
{
    //  R = S*f + D*(1-f) = (S-D)*f + D
    Scratch scratches(registerFile());
    // compute D-S
    integer_t diff(fb.flags & CORRUPTIBLE ?
                   fb.reg : scratches.obtain(), fb.size(), CORRUPTIBLE);
    const int shift = fragment.size() - fb.size();
    if (shift>0) {
        SHR(shift, fragment.reg);
        MOV_REG_TO_REG(fb.reg, diff.reg);
        SUB_REG_TO_REG(fragment.reg, diff.reg);
    }
    else if (shift<0) {
        SHR(-shift, fragment.reg);
        MOV_REG_TO_REG(fb.reg, diff.reg);
        SUB_REG_TO_REG(fragment.reg, diff.reg);
    }
    else    {
        MOV_REG_TO_REG(fb.reg, diff.reg);
        SUB_REG_TO_REG(fragment.reg, diff.reg);
    }

    mul_factor_add(temp, diff, factor, component_t(fragment));
    if(!(fragment.flags & CORRUPTIBLE))
        scratches.recycle(diff.reg);
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::mul_factor(  component_t& d,
                                   const integer_t& v,
                                   const integer_t& f, Scratch& scratches)
{
    // f can be changed
    //
    int vs = v.size();
    int fs = f.size();
    int ms = vs+fs;

    // XXX: we could have special cases for 1 bit mul

    // all this code below to use the best multiply instruction
    // wrt the parameters size. We take advantage of the fact
    // that the 16-bits multiplies allow a 16-bit shift
    // The trick is that we just make sure that we have at least 8-bits
    // per component (which is enough for a 8 bits display).

    int xy = -1;
    int vshift = 0;
    int fshift = 0;
    int smulw = 0;

    int xyBB = 0;
    int xyTB = 1;
    int xyTT = 2;
    int xyBT = 3;
    if (vs<16) {
        if (fs<16) {
            xy = xyBB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            ms -= 16;
            xy = xyTB;
        } else {
            // eg: 15 * 18  ->  15 * 15
            fshift = fs - 15;
            ms -= fshift;
            xy = xyBB;
        }
    } else if (GGL_BETWEEN(vs, 24, 31)) {
        if (fs<16) {
            ms -= 16;
            xy = xyTB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            ms -= 32;
            xy = xyTT;
        } else {
            // eg: 24 * 18  ->  8 * 18
            fshift = fs - 15;
            ms -= 16 + fshift;
            xy = xyTB;
        }
    } else {
        if (fs<16) {
            // eg: 18 * 15  ->  15 * 15
            vshift = vs - 15;
            ms -= vshift;
            xy = xyBB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            // eg: 18 * 24  ->  15 * 8
            vshift = vs - 15;
            ms -= 16 + vshift;
            xy = xyBT;
        } else {
            // eg: 18 * 18  ->  (15 * 18)>>16
            fshift = fs - 15;
            ms -= 16 + fshift;
            //xy = yB;    //XXX SMULWB
            smulw = 1;
        }
    }

    ALOGE_IF(ms>=32, "mul_factor overflow vs=%d, fs=%d", vs, fs);

    int vreg = v.reg;
    int freg = f.reg;
    if (vshift) {
        MOV_REG_TO_REG(vreg, d.reg);
        SHR(vshift, d.reg);
        vreg = d.reg;
    }
    if (fshift) {
        MOV_REG_TO_REG(vreg, d.reg);
        SHR(fshift, d.reg);
        freg = d.reg;
    }
    MOV_REG_TO_REG(vreg, d.reg);
    if (smulw) {
        int flag_push_edx = 0;
        int flag_reserve_edx = 0;
        int temp_reg2 = -1;
        int edx_offset_ebp = 0;
        if(scratches.isUsed(EDX) == 1) {
            if(d.reg != EDX) {
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
            if( freg == EAX || d.reg == EAX) {
                MOVSX_REG_TO_REG(OpndSize_16, freg, freg);
                if(freg == EAX)
                    IMUL(d.reg);
                else
                    IMUL(freg);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, d.reg);
            }
            else {
                int eax_offset_ebp = 0;
                if(scratches.countFreeRegs() > 0) {
                    temp_reg2 = scratches.obtain();
                    MOV_REG_TO_REG(EAX, temp_reg2);
                }
                else {
                    mCurSp = mCurSp - 4;
                    eax_offset_ebp = mCurSp;
                    MOV_REG_TO_MEM(EAX, eax_offset_ebp, EBP);
                    //PUSH(EAX);
                }
                MOV_REG_TO_REG(freg, EAX);
                MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                IMUL(d.reg);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, d.reg);
                if(temp_reg2 > -1) {
                    MOV_REG_TO_REG(temp_reg2, EAX);
                    scratches.recycle(temp_reg2);
                }
                else {
                    MOV_MEM_TO_REG(eax_offset_ebp, EBP, EAX);
                    //POP(EAX);
                }
            }
        }
        else {
            MOV_REG_TO_REG(freg, EAX);
            MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
            IMUL(d.reg);
            SHL(16, EDX);
            SHR(16, EAX);
            MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
            MOV_REG_TO_REG(EDX, d.reg);
        }
        if(flag_push_edx == 1) {
            MOV_MEM_TO_REG(edx_offset_ebp, EBP, EDX);
            //POP(EDX);
        }
        if(flag_reserve_edx ==1)
            scratches.recycle(EDX);
    }
    else {
        if(xy == xyBB) {
            MOVSX_REG_TO_REG(OpndSize_16, d.reg, d.reg);
            MOVSX_REG_TO_REG(OpndSize_16, freg, freg);
            IMUL(freg, d.reg);
        }
        else if(xy == xyTB) {
            SHR(16, d.reg);
            MOVSX_REG_TO_REG(OpndSize_16, d.reg, d.reg);
            MOVSX_REG_TO_REG(OpndSize_16, freg, freg);
            IMUL(freg, d.reg);
        }
        else if(xy == xyBT) {
            MOVSX_REG_TO_REG(OpndSize_16, d.reg, d.reg);
            SHR(16, freg);
            MOVSX_REG_TO_REG(OpndSize_16, freg, freg);
            IMUL(freg, d.reg);
        }
        else if(xy == xyTT) {
            SHR(16, d.reg);
            MOVSX_REG_TO_REG(OpndSize_16, d.reg, d.reg);
            SHR(16, freg);
            MOVSX_REG_TO_REG(OpndSize_16, freg, freg);
            IMUL(freg, d.reg);
        }
    }


    d.h = ms;
    if (mDithering) {
        d.l = 0;
    } else {
        d.l = fs;
        d.flags |= CLEAR_LO;
    }
}

void GGLX86Assembler::mul_factor_add(  component_t& d,
                                       const integer_t& v,
                                       const integer_t& f,
                                       const component_t& a)
{
    // XXX: we could have special cases for 1 bit mul
    Scratch scratches(registerFile());

    int vs = v.size();
    int fs = f.size();
    int as = a.h;
    int ms = vs+fs;

    ALOGE_IF(ms>=32, "mul_factor_add overflow vs=%d, fs=%d, as=%d", vs, fs, as);

    integer_t add(a.reg, a.h, a.flags, a.offset_ebp);


    // 'a' is a component_t but it is guaranteed to have
    // its high bits set to 0. However in the dithering case,
    // we can't get away with truncating the potentially bad bits
    // so extraction is needed.

    if ((mDithering) && (a.size() < ms)) {
        // we need to expand a
        if (!(a.flags & CORRUPTIBLE)) {
            // ... but it's not corruptible, so we need to pick a
            // temporary register.
            // Try to uses the destination register first (it's likely
            // to be usable, unless it aliases an input).
            if (d.reg!=a.reg && d.reg!=v.reg && d.reg!=f.reg) {
                add.reg = d.reg;
            } else {
                add.reg = scratches.obtain();
            }
        }
        expand(add, a, ms); // extracts and expands
        as = ms;
    }

    if (ms == as) {
        MOV_REG_TO_REG(v.reg, d.reg);
        if (vs<16 && fs<16) {
            MOVSX_REG_TO_REG(OpndSize_16, d.reg, d.reg);
            MOVSX_REG_TO_REG(OpndSize_16, f.reg, f.reg);
            IMUL(f.reg, d.reg);
        }
        else
            IMUL(f.reg, d.reg);
        ADD_REG_TO_REG(add.reg, d.reg);
    } else {
        //int temp = d.reg;
        //if (temp == add.reg) {
        //    // the mul will modify add.reg, we need an intermediary reg
        //    if (v.flags & CORRUPTIBLE)      temp = v.reg;
        //    else if (f.flags & CORRUPTIBLE) temp = f.reg;
        //    else                            temp = scratches.obtain();
        //}

        // below d.reg may override "temp" result, so we use a new register
        int temp_reg;
        int v_offset_ebp = 0;
        if(scratches.countFreeRegs() == 0) {
            temp_reg = v.reg;
            mCurSp = mCurSp - 4;
            v_offset_ebp = mCurSp;
            MOV_REG_TO_MEM(v.reg, v_offset_ebp, EBP);
        }
        else {
            temp_reg = scratches.obtain();
            MOV_REG_TO_REG(v.reg, temp_reg);
        }
        if (vs<16 && fs<16) {
            MOVSX_REG_TO_REG(OpndSize_16, temp_reg, temp_reg);
            MOVSX_REG_TO_REG(OpndSize_16, f.reg, f.reg);
            IMUL(f.reg, temp_reg);
        }
        else
            IMUL(f.reg, temp_reg);

        if (ms>as) {
            MOV_REG_TO_REG(add.reg, d.reg);
            SHL(ms-as, d.reg);
            ADD_REG_TO_REG(temp_reg, d.reg);
        } else if (ms<as) {
            // not sure if we should expand the mul instead?
            MOV_REG_TO_REG(add.reg, d.reg);
            SHL(as-ms, d.reg);
            ADD_REG_TO_REG(temp_reg, d.reg);
        }
        if(temp_reg == v.reg)
            MOV_MEM_TO_REG(v_offset_ebp, EBP, v.reg);
        else
            scratches.recycle(temp_reg);
    }

    d.h = ms;
    if (mDithering) {
        d.l = a.l;
    } else {
        d.l = fs>a.l ? fs : a.l;
        d.flags |= CLEAR_LO;
    }
}

void GGLX86Assembler::component_add(component_t& d,
                                    const integer_t& dst, const integer_t& src)
{
    // here we're guaranteed that fragment.size() >= fb.size()
    const int shift = src.size() - dst.size();
    if (!shift) {
        MOV_REG_TO_REG(src.reg, d.reg);
        ADD_REG_TO_REG(dst.reg, d.reg);
    } else {
        MOV_REG_TO_REG(dst.reg, d.reg);
        SHL(shift, d.reg);
        ADD_REG_TO_REG(src.reg, d.reg);
    }

    d.h = src.size();
    if (mDithering) {
        d.l = 0;
    } else {
        d.l = shift;
        d.flags |= CLEAR_LO;
    }
}

void GGLX86Assembler::component_sat(const component_t& v, const int temp_reg)
{
    const int32_t one = ((1<<v.size())-1)<<v.l;
    MOV_IMM_TO_REG(one, temp_reg);
    CMP_IMM_TO_REG(1<<v.h, v.reg);
    CMOV_REG_TO_REG(Mnemonic_CMOVAE, temp_reg, v.reg);
}

// ----------------------------------------------------------------------------

}; // namespace android
