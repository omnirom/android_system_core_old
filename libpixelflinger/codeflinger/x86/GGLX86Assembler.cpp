/* libs/pixelflinger/codeflinger/x86/GGLX86Assembler.cpp
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

#define LOG_TAG "GGLX86Assembler"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <cutils/log.h>

#include "codeflinger/x86/GGLX86Assembler.h"

namespace android {

// ----------------------------------------------------------------------------

GGLX86Assembler::GGLX86Assembler(const sp<Assembly>& assembly)
    : X86Assembler(assembly), X86RegisterAllocator(), mOptLevel(7)
{
}

GGLX86Assembler::~GGLX86Assembler()
{
}

void GGLX86Assembler::reset(int opt_level)
{
    X86Assembler::reset();
    X86RegisterAllocator::reset();
    mOptLevel = opt_level;
}

// ---------------------------------------------------------------------------

int GGLX86Assembler::scanline(const needs_t& needs, context_t const* c)
{
    int err = 0;
    err = scanline_core(needs, c);
    if (err != 0)
        ALOGE("scanline_core failed probably due to running out of the registers: %d\n", err);

    // XXX: in theory, pcForLabel is not valid before generate()
    char* fragment_start_pc = pcForLabel("fragment_loop");
    char* fragment_end_pc = pcForLabel("fragment_end");
    const int per_fragment_ins_size = int(fragment_end_pc - fragment_start_pc);

    // build a name for our pipeline
    char name[128];
    sprintf(name,
            "scanline__%08X:%08X_%08X_%08X [%3d ipp ins size]",
            needs.p, needs.n, needs.t[0], needs.t[1], per_fragment_ins_size);

    if (err) {
        ALOGE("Error while generating ""%s""\n", name);
        disassemble(name);
        return -1;
    }

    return generate(name);
}

int GGLX86Assembler::scanline_core(const needs_t& needs, context_t const* c)
{
    int64_t duration = ggl_system_time();

    mBlendFactorCached = 0;
    mBlending = 0;
    mMasking = 0;
    mAA        = GGL_READ_NEEDS(P_AA, needs.p);
    mDithering = GGL_READ_NEEDS(P_DITHER, needs.p);
    mAlphaTest = GGL_READ_NEEDS(P_ALPHA_TEST, needs.p) + GGL_NEVER;
    mDepthTest = GGL_READ_NEEDS(P_DEPTH_TEST, needs.p) + GGL_NEVER;
    mFog       = GGL_READ_NEEDS(P_FOG, needs.p) != 0;
    mSmooth    = GGL_READ_NEEDS(SHADE, needs.n) != 0;
    mBuilderContext.needs = needs;
    mBuilderContext.c = c;
    mBuilderContext.Rctx = obtainReg(); //dynamically obtain if used and then immediately recycle it if not used
    mCbFormat = c->formats[ GGL_READ_NEEDS(CB_FORMAT, needs.n) ];

    // ------------------------------------------------------------------------

    decodeLogicOpNeeds(needs);

    decodeTMUNeeds(needs, c);

    mBlendSrc  = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_SRC, needs.n));
    mBlendDst  = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_DST, needs.n));
    mBlendSrcA = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_SRCA, needs.n));
    mBlendDstA = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_DSTA, needs.n));

    if (!mCbFormat.c[GGLFormat::ALPHA].h) {
        if ((mBlendSrc == GGL_ONE_MINUS_DST_ALPHA) ||
                (mBlendSrc == GGL_DST_ALPHA)) {
            mBlendSrc = GGL_ONE;
        }
        if ((mBlendSrcA == GGL_ONE_MINUS_DST_ALPHA) ||
                (mBlendSrcA == GGL_DST_ALPHA)) {
            mBlendSrcA = GGL_ONE;
        }
        if ((mBlendDst == GGL_ONE_MINUS_DST_ALPHA) ||
                (mBlendDst == GGL_DST_ALPHA)) {
            mBlendDst = GGL_ONE;
        }
        if ((mBlendDstA == GGL_ONE_MINUS_DST_ALPHA) ||
                (mBlendDstA == GGL_DST_ALPHA)) {
            mBlendDstA = GGL_ONE;
        }
    }

    // if we need the framebuffer, read it now
    const int blending =    blending_codes(mBlendSrc, mBlendDst) |
                            blending_codes(mBlendSrcA, mBlendDstA);

    // XXX: handle special cases, destination not modified...
    if ((mBlendSrc==GGL_ZERO) && (mBlendSrcA==GGL_ZERO) &&
            (mBlendDst==GGL_ONE) && (mBlendDstA==GGL_ONE)) {
        // Destination unmodified (beware of logic ops)
    } else if ((mBlendSrc==GGL_ZERO) && (mBlendSrcA==GGL_ZERO) &&
               (mBlendDst==GGL_ZERO) && (mBlendDstA==GGL_ZERO)) {
        // Destination is zero (beware of logic ops)
    }

    int fbComponents = 0;
    const int masking = GGL_READ_NEEDS(MASK_ARGB, needs.n);
    for (int i=0 ; i<4 ; i++) {
        const int mask = 1<<i;
        component_info_t& info = mInfo[i];
        int fs = i==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
        int fd = i==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
        if (fs==GGL_SRC_ALPHA_SATURATE && i==GGLFormat::ALPHA)
            fs = GGL_ONE;
        info.masked =   !!(masking & mask);
        info.inDest =   !info.masked && mCbFormat.c[i].h &&
                        ((mLogicOp & LOGIC_OP_SRC) || (!mLogicOp));
        if (mCbFormat.components >= GGL_LUMINANCE &&
                (i==GGLFormat::GREEN || i==GGLFormat::BLUE)) {
            info.inDest = false;
        }
        info.needed =   (i==GGLFormat::ALPHA) &&
                        (isAlphaSourceNeeded() || mAlphaTest != GGL_ALWAYS);
        info.replaced = !!(mTextureMachine.replaced & mask);
        info.iterated = (!info.replaced && (info.inDest || info.needed));
        info.smooth =   mSmooth && info.iterated;
        info.fog =      mFog && info.inDest && (i != GGLFormat::ALPHA);
        info.blend =    (fs != int(GGL_ONE)) || (fd > int(GGL_ZERO));

        mBlending |= (info.blend ? mask : 0);
        mMasking |= (mCbFormat.c[i].h && info.masked) ? mask : 0;
        fbComponents |= mCbFormat.c[i].h ? mask : 0;
    }

    mAllMasked = (mMasking == fbComponents);
    if (mAllMasked) {
        mDithering = 0;
    }

    fragment_parts_t parts;

    // ------------------------------------------------------------------------
    callee_work();
    // ------------------------------------------------------------------------

    mCurSp = -12; // %ebx, %edi, %esi
    prepare_esp(0);
    build_scanline_preparation(parts, needs);
    recycleReg(mBuilderContext.Rctx);

    if (registerFile().status())
        return registerFile().status();

    // ------------------------------------------------------------------------
    label("fragment_loop");
    // ------------------------------------------------------------------------
    {
        Scratch regs(registerFile());
        int temp_reg = -1;

        if (mDithering) {
            // update the dither index.
            temp_reg = regs.obtain();
            //To load to register and calculate should be fast than the memory operations
            MOV_MEM_TO_REG(parts.count.offset_ebp, PhysicalReg_EBP, temp_reg);
            ROR(GGL_DITHER_ORDER_SHIFT, temp_reg);
            ADD_IMM_TO_REG(1 << (32 - GGL_DITHER_ORDER_SHIFT), temp_reg);
            ROR(32 - GGL_DITHER_ORDER_SHIFT, temp_reg);
            MOV_REG_TO_MEM(temp_reg, parts.count.offset_ebp, PhysicalReg_EBP);
            regs.recycle(temp_reg);

        }

        // XXX: could we do an early alpha-test here in some cases?
        // It would probaly be used only with smooth-alpha and no texture
        // (or no alpha component in the texture).

        // Early z-test
        if (mAlphaTest==GGL_ALWAYS) {
            build_depth_test(parts, Z_TEST|Z_WRITE);
        } else {
            // we cannot do the z-write here, because
            // it might be killed by the alpha-test later
            build_depth_test(parts, Z_TEST);
        }

        {   // texture coordinates
            Scratch scratches(registerFile());

            // texel generation
            build_textures(parts, regs);

        }

        if ((blending & (FACTOR_DST|BLEND_DST)) ||
                (mMasking && !mAllMasked) ||
                (mLogicOp & LOGIC_OP_DST))
        {
            // blending / logic_op / masking need the framebuffer
            mDstPixel.setTo(regs.obtain(), &mCbFormat);

            // load the framebuffer pixel
            comment("fetch color-buffer");
            parts.cbPtr.reg = regs.obtain();
            MOV_MEM_TO_REG(parts.cbPtr.offset_ebp, PhysicalReg_EBP, parts.cbPtr.reg);
            load(parts.cbPtr, mDstPixel);
            mCurSp = mCurSp - 4;
            mDstPixel.offset_ebp = mCurSp;
            MOV_REG_TO_MEM(mDstPixel.reg, mDstPixel.offset_ebp, EBP);
            regs.recycle(mDstPixel.reg);
            regs.recycle(parts.cbPtr.reg);
            mDstPixel.reg = -1;
        }

        if (registerFile().status())
            return registerFile().status();

        pixel_t pixel;
        int directTex = mTextureMachine.directTexture;
        if (directTex | parts.packed) {
            // note: we can't have both here
            // iterated color or direct texture
            if(directTex) {
                pixel.offset_ebp = parts.texel[directTex-1].offset_ebp;
            }
            else
                pixel.offset_ebp = parts.iterated.offset_ebp;
            pixel.reg = regs.obtain();
            MOV_MEM_TO_REG(pixel.offset_ebp, EBP, pixel.reg);
            //pixel = directTex ? parts.texel[directTex-1] : parts.iterated;
            pixel.flags &= ~CORRUPTIBLE;
        } else {
            if (mDithering) {
                mBuilderContext.Rctx = regs.obtain();
                temp_reg = regs.obtain();
                const int ctxtReg = mBuilderContext.Rctx;
                MOV_MEM_TO_REG(8, EBP, ctxtReg);
                const int mask = GGL_DITHER_SIZE-1;
                parts.dither = reg_t(regs.obtain());
                MOV_MEM_TO_REG(parts.count.offset_ebp, EBP, parts.dither.reg);
                AND_IMM_TO_REG(mask, parts.dither.reg);
                ADD_REG_TO_REG(ctxtReg, parts.dither.reg);
                MOVZX_MEM_TO_REG(OpndSize_8, parts.dither.reg, GGL_OFFSETOF(ditherMatrix), temp_reg);
                MOV_REG_TO_REG(temp_reg, parts.dither.reg);
                mCurSp = mCurSp - 4;
                parts.dither.offset_ebp = mCurSp;
                MOV_REG_TO_MEM(parts.dither.reg, parts.dither.offset_ebp, EBP);
                regs.recycle(parts.dither.reg);
                regs.recycle(temp_reg);
                regs.recycle(mBuilderContext.Rctx);

            }

            // allocate a register for the resulting pixel
            pixel.setTo(regs.obtain(), &mCbFormat, FIRST);

            build_component(pixel, parts, GGLFormat::ALPHA,    regs);

            if (mAlphaTest!=GGL_ALWAYS) {
                // only handle the z-write part here. We know z-test
                // was successful, as well as alpha-test.
                build_depth_test(parts, Z_WRITE);
            }

            build_component(pixel, parts, GGLFormat::RED,      regs);
            build_component(pixel, parts, GGLFormat::GREEN,    regs);
            build_component(pixel, parts, GGLFormat::BLUE,     regs);

            pixel.flags |= CORRUPTIBLE;
        }

        if (registerFile().status()) {
            return registerFile().status();
        }

        if (pixel.reg == -1) {
            // be defensive here. if we're here it's probably
            // that this whole fragment is a no-op.
            pixel = mDstPixel;
        }

        if (!mAllMasked) {
            // logic operation
            build_logic_op(pixel, regs);

            // masking
            build_masking(pixel, regs);

            comment("store");
            parts.cbPtr.reg = regs.obtain();
            MOV_MEM_TO_REG(parts.cbPtr.offset_ebp, EBP, parts.cbPtr.reg);
            store(parts.cbPtr, pixel, WRITE_BACK);
            MOV_REG_TO_MEM(parts.cbPtr.reg, parts.cbPtr.offset_ebp, EBP);
            regs.recycle(parts.cbPtr.reg);
            regs.recycle(pixel.reg);
        }
    }

    if (registerFile().status())
        return registerFile().status();

    // update the iterated color...
    if (parts.reload != 3) {
        build_smooth_shade(parts);
    }

    // update iterated z
    build_iterate_z(parts);

    // update iterated fog
    build_iterate_f(parts);

    //SUB_IMM_TO_REG(1<<16, parts.count.reg);
    SUB_IMM_TO_MEM(1<<16, parts.count.offset_ebp, EBP);

    JCC(Mnemonic_JNS, "fragment_loop");
    label("fragment_end");
    int update_esp_offset, shrink_esp_offset;
    update_esp_offset = shrink_esp_offset = -mCurSp - 12; // 12 is ebx, esi, edi
    update_esp(update_esp_offset);
    shrink_esp(shrink_esp_offset);
    return_work();

    if ((mAlphaTest!=GGL_ALWAYS) || (mDepthTest!=GGL_ALWAYS)) {
        if (mDepthTest!=GGL_ALWAYS) {
            label("discard_before_textures");
            build_iterate_texture_coordinates(parts);
        }
        label("discard_after_textures");
        build_smooth_shade(parts);
        build_iterate_z(parts);
        build_iterate_f(parts);
        if (!mAllMasked) {
            //ADD_IMM_TO_REG(parts.cbPtr.size>>3, parts.cbPtr.reg);
            ADD_IMM_TO_MEM(parts.cbPtr.size>>3, parts.cbPtr.offset_ebp, EBP);
        }
        SUB_IMM_TO_MEM(1<<16, parts.count.offset_ebp, EBP);
        //SUB_IMM_TO_REG(1<<16, parts.count.reg);
        JCC(Mnemonic_JNS, "fragment_loop");
        update_esp_offset = shrink_esp_offset = -mCurSp - 12; // 12 is ebx, esi, edi
        update_esp(update_esp_offset);
        shrink_esp(shrink_esp_offset);
        return_work();
    }

    return registerFile().status();
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_scanline_preparation(
    fragment_parts_t& parts, const needs_t& needs)
{
    Scratch scratches(registerFile());

    // compute count
    comment("compute ct (# of pixels to process)");
    int temp_reg;
    parts.count.setTo(obtainReg());
    int Rx = scratches.obtain();
    int Ry = scratches.obtain();
    // the only argument is +8 bytes relative to the current EBP
    MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
    CONTEXT_LOAD(Rx, iterators.xl);
    CONTEXT_LOAD(parts.count.reg, iterators.xr);
    CONTEXT_LOAD(Ry, iterators.y);

    // parts.count = iterators.xr - Rx
    SUB_REG_TO_REG(Rx, parts.count.reg);
    SUB_IMM_TO_REG(1, parts.count.reg);

    if (mDithering) {
        // parts.count.reg = 0xNNNNXXDD
        // NNNN = count-1
        // DD   = dither offset
        // XX   = 0xxxxxxx (x = garbage)
        Scratch scratches(registerFile());
        int tx = scratches.obtain();
        int ty = scratches.obtain();

        MOV_REG_TO_REG(Rx,tx);
        AND_IMM_TO_REG(GGL_DITHER_MASK, tx);
        MOV_REG_TO_REG(Ry,ty);
        AND_IMM_TO_REG(GGL_DITHER_MASK, ty);
        SHL(GGL_DITHER_ORDER_SHIFT, ty);
        ADD_REG_TO_REG(ty, tx);
        SHL(16, parts.count.reg);
        OR_REG_TO_REG(tx, parts.count.reg);
        scratches.recycle(tx);
        scratches.recycle(ty);
    } else {
        // parts.count.reg = 0xNNNN0000
        // NNNN = count-1
        SHL(16, parts.count.reg);
    }
    mCurSp = mCurSp - 4;
    parts.count.offset_ebp = mCurSp; //ebx, esi, edi, parts.count.reg
    MOV_REG_TO_MEM(parts.count.reg, parts.count.offset_ebp, EBP);
    //PUSH(parts.count.reg);
    recycleReg(parts.count.reg);
    parts.count.reg=-1;
    if (!mAllMasked) {
        // compute dst ptr
        comment("compute color-buffer pointer");
        const int cb_bits = mCbFormat.size*8;
        int Rs = scratches.obtain();
        temp_reg = scratches.obtain();
        CONTEXT_LOAD(Rs, state.buffers.color.stride);
        MOVSX_REG_TO_REG(OpndSize_16, Ry, temp_reg);
        MOVSX_REG_TO_REG(OpndSize_16, Rs, Rs);
        IMUL(temp_reg, Rs);
        scratches.recycle(temp_reg);
        ADD_REG_TO_REG(Rx, Rs);

        parts.cbPtr.setTo(obtainReg(), cb_bits);
        CONTEXT_LOAD(parts.cbPtr.reg, state.buffers.color.data);
        reg_t temp_reg_t;
        temp_reg_t.setTo(Rs);
        base_offset(parts.cbPtr, parts.cbPtr, temp_reg_t);

        mCurSp = mCurSp - 4;
        parts.cbPtr.offset_ebp = mCurSp; //ebx, esi, edi, parts.count.reg, parts.cbPtr.reg
        MOV_REG_TO_MEM(parts.cbPtr.reg, parts.cbPtr.offset_ebp, EBP);
        //PUSH(parts.cbPtr.reg);
        recycleReg(parts.cbPtr.reg);
        parts.cbPtr.reg=-1;
        scratches.recycle(Rs);
    }

    // init fog
    const int need_fog = GGL_READ_NEEDS(P_FOG, needs.p);
    if (need_fog) {
        comment("compute initial fog coordinate");
        Scratch scratches(registerFile());
        int ydfdy = scratches.obtain();
        int dfdx = scratches.obtain();
        CONTEXT_LOAD(dfdx,  generated_vars.dfdx);
        IMUL(Rx, dfdx);
        CONTEXT_LOAD(ydfdy, iterators.ydfdy);
        ADD_REG_TO_REG(ydfdy, dfdx); // Rx * dfdx + ydfdy
        CONTEXT_STORE(dfdx, generated_vars.f);
        scratches.recycle(dfdx);
        scratches.recycle(ydfdy);
    }

    // init Z coordinate
    if ((mDepthTest != GGL_ALWAYS) || GGL_READ_NEEDS(P_MASK_Z, needs.p)) {
        parts.z = reg_t(obtainReg());
        comment("compute initial Z coordinate");
        Scratch scratches(registerFile());
        int dzdx = scratches.obtain();
        int ydzdy = parts.z.reg;
        CONTEXT_LOAD(dzdx,  generated_vars.dzdx);   // 1.31 fixed-point
        IMUL(Rx, dzdx);
        CONTEXT_LOAD(ydzdy, iterators.ydzdy);       // 1.31 fixed-point
        ADD_REG_TO_REG(dzdx, ydzdy);  // parts.z.reg = Rx * dzdx + ydzdy

        mCurSp = mCurSp - 4;
        parts.z.offset_ebp = mCurSp; //ebx, esi, edi, parts.count.reg, parts.cbPtr.reg, parts.z.reg
        MOV_REG_TO_MEM(ydzdy, parts.z.offset_ebp, EBP);
        //PUSH(ydzdy);
        recycleReg(ydzdy);
        parts.z.reg=-1;

        // we're going to index zbase of parts.count
        // zbase = base + (xl-count + stride*y)*2 by arm
        // !!! Actually, zbase = base + (xl + stride*y)*2
        int Rs = dzdx;
        int zbase = scratches.obtain();
        temp_reg = zbase;
        CONTEXT_LOAD(Rs, state.buffers.depth.stride);
        MOVSX_REG_TO_REG(OpndSize_16, Rs, Rs);
        MOV_REG_TO_REG(Ry, temp_reg);
        MOVSX_REG_TO_REG(OpndSize_16, temp_reg, temp_reg);
        IMUL(temp_reg, Rs);
        ADD_REG_TO_REG(Rx, Rs);
        // load parts.count.reg
        MOV_MEM_TO_REG(parts.count.offset_ebp, EBP, temp_reg);
        SHR(16, temp_reg);
        ADD_REG_TO_REG(temp_reg, Rs);
        SHL(1, Rs);
        CONTEXT_LOAD(zbase, state.buffers.depth.data);
        ADD_REG_TO_REG(Rs, zbase);
        CONTEXT_STORE(zbase, generated_vars.zbase);
        scratches.recycle(zbase);
        scratches.recycle(dzdx);
    }
    // the rgisters are all used up

    // init texture coordinates
    init_textures(parts.coords, reg_t(Rx), reg_t(Ry));
    scratches.recycle(Ry);

    // iterated color
    init_iterated_color(parts, reg_t(Rx));

    // init coverage factor application (anti-aliasing)
    if (mAA) {
        parts.covPtr.setTo(obtainReg(), 16);
        CONTEXT_LOAD(parts.covPtr.reg, state.buffers.coverage);
        SHL(1, Rx);
        ADD_REG_TO_REG(Rx, parts.covPtr.reg);

        mCurSp = mCurSp - 4;
        parts.covPtr.offset_ebp = mCurSp;
        MOV_REG_TO_MEM(parts.covPtr.reg, parts.covPtr.offset_ebp, EBP);
        //PUSH(parts.covPtr.reg);
        recycleReg(parts.covPtr.reg);
        parts.covPtr.reg=-1;
    }
    scratches.recycle(Rx);
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_component( pixel_t& pixel,
                                       fragment_parts_t& parts,
                                       int component,
                                       Scratch& regs)
{
    static char const * comments[] = {"alpha", "red", "green", "blue"};
    comment(comments[component]);

    // local register file
    Scratch scratches(registerFile());
    const int dst_component_size = pixel.component_size(component);

    component_t temp(-1);
    build_incoming_component( temp, dst_component_size,
                              parts, component, scratches, regs);

    if (mInfo[component].inDest) {
        // blending...
        build_blending( temp, mDstPixel, component, scratches );

        // downshift component and rebuild pixel...
        downshift(pixel, component, temp, parts.dither);
    }
}

void GGLX86Assembler::build_incoming_component(
    component_t& temp,
    int dst_size,
    fragment_parts_t& parts,
    int component,
    Scratch& scratches,
    Scratch& global_regs)
{
    const uint32_t component_mask = 1<<component;

    // Figure out what we need for the blending stage...
    int fs = component==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
    int fd = component==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
    if (fs==GGL_SRC_ALPHA_SATURATE && component==GGLFormat::ALPHA) {
        fs = GGL_ONE;
    }

    // Figure out what we need to extract and for what reason
    const int blending = blending_codes(fs, fd);

    // Are we actually going to blend?
    const int need_blending = (fs != int(GGL_ONE)) || (fd > int(GGL_ZERO));

    // expand the source if the destination has more bits
    int need_expander = false;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT-1 ; i++) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];
        if ((tmu.format_idx) &&
                (parts.texel[i].component_size(component) < dst_size)) {
            need_expander = true;
        }
    }

    // do we need to extract this component?
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    const int blend_needs_alpha_source = (component==GGLFormat::ALPHA) &&
                                         (isAlphaSourceNeeded());
    int need_extract = mInfo[component].needed;
    if (mInfo[component].inDest)
    {
        need_extract |= ((need_blending ?
                          (blending & (BLEND_SRC|FACTOR_SRC)) : need_expander));
        need_extract |= (mTextureMachine.mask != mTextureMachine.replaced);
        need_extract |= mInfo[component].smooth;
        need_extract |= mInfo[component].fog;
        need_extract |= mDithering;
        need_extract |= multiTexture;
    }

    if (need_extract) {
        Scratch& regs = blend_needs_alpha_source ? global_regs : scratches;
        component_t fragment;

        // iterated color
        fragment.setTo( regs.obtain(), 0, 32, CORRUPTIBLE);
        build_iterated_color(fragment, parts, component, regs);

        // texture environment (decal, modulate, replace)
        build_texture_environment(fragment, parts, component, regs);

        // expand the source if the destination has more bits
        if (need_expander && (fragment.size() < dst_size)) {
            // we're here only if we fetched a texel
            // (so we know for sure fragment is CORRUPTIBLE)
            //fragment is stored on the stack
            expand(fragment, fragment, dst_size);
        }

        mCurSp = mCurSp - 4;
        fragment.offset_ebp = mCurSp;
        MOV_REG_TO_MEM(fragment.reg, fragment.offset_ebp, EBP);
        regs.recycle(fragment.reg);

        // We have a few specific things to do for the alpha-channel
        if ((component==GGLFormat::ALPHA) &&
                (mInfo[component].needed || fragment.size()<dst_size))
        {
            // convert to integer_t first and make sure
            // we don't corrupt a needed register
            if (fragment.l) {
                //component_t incoming(fragment);
                // actually fragment is not corruptible
                //modify(fragment, regs);
                //MOV_REG_TO_REG(incoming.reg, fragment.reg);
                SHR(fragment.l, fragment.offset_ebp, EBP);
                fragment.h -= fragment.l;
                fragment.l = 0;
            }

            // I haven't found any case to trigger coverage and the following alpha test (mAlphaTest != GGL_ALWAYS)
            fragment.reg = regs.obtain();
            MOV_MEM_TO_REG(fragment.offset_ebp, EBP, fragment.reg);

            // coverage factor application
            build_coverage_application(fragment, parts, regs);
            // alpha-test
            build_alpha_test(fragment, parts);

            MOV_REG_TO_MEM(fragment.reg, fragment.offset_ebp, EBP);
            regs.recycle(fragment.reg);

            if (blend_needs_alpha_source) {
                // We keep only 8 bits for the blending stage
                const int shift = fragment.h <= 8 ? 0 : fragment.h-8;

                if (fragment.flags & CORRUPTIBLE) {
                    fragment.flags &= ~CORRUPTIBLE;
                    mAlphaSource.setTo(fragment.reg,
                                       fragment.size(), fragment.flags, fragment.offset_ebp);
                    //mCurSp = mCurSp - 4;
                    //mAlphaSource.offset_ebp = mCurSp;
                    if (shift) {
                        SHR(shift, mAlphaSource.offset_ebp, EBP);
                    }
                } else {
                    // XXX: it would better to do this in build_blend_factor()
                    // so we can avoid the extra MOV below.
                    mAlphaSource.setTo(regs.obtain(),
                                       fragment.size(), CORRUPTIBLE);
                    mCurSp = mCurSp - 4;
                    mAlphaSource.offset_ebp = mCurSp;
                    if (shift) {
                        MOV_MEM_TO_REG(fragment.offset_ebp, EBP, mAlphaSource.reg);
                        SHR(shift, mAlphaSource.reg);
                    } else {
                        MOV_MEM_TO_REG(fragment.offset_ebp, EBP, mAlphaSource.reg);
                    }
                    MOV_REG_TO_MEM(mAlphaSource.reg, mAlphaSource.offset_ebp, EBP);
                    regs.recycle(mAlphaSource.reg);
                }
                mAlphaSource.s -= shift;

            }
        }

        // fog...
        build_fog( fragment, component, regs );

        temp = fragment;
    } else {
        if (mInfo[component].inDest) {
            // extraction not needed and replace
            // we just select the right component
            if ((mTextureMachine.replaced & component_mask) == 0) {
                // component wasn't replaced, so use it!
                temp = component_t(parts.iterated, component);
            }
            for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; i++) {
                const texture_unit_t& tmu = mTextureMachine.tmu[i];
                if ((tmu.mask & component_mask) &&
                        ((tmu.replaced & component_mask) == 0)) {
                    temp = component_t(parts.texel[i], component);
                }
            }
        }
    }
}

bool GGLX86Assembler::isAlphaSourceNeeded() const
{
    // XXX: also needed for alpha-test
    const int bs = mBlendSrc;
    const int bd = mBlendDst;
    return  bs==GGL_SRC_ALPHA_SATURATE ||
            bs==GGL_SRC_ALPHA || bs==GGL_ONE_MINUS_SRC_ALPHA ||
            bd==GGL_SRC_ALPHA || bd==GGL_ONE_MINUS_SRC_ALPHA ;
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_smooth_shade(fragment_parts_t& parts)
{
    if (mSmooth && !parts.iterated_packed) {
        // update the iterated color in a pipelined way...
        comment("update iterated color");
        Scratch scratches(registerFile());
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);

        const int reload = parts.reload;
        for (int i=0 ; i<4 ; i++) {
            if (!mInfo[i].iterated)
                continue;

            int dx = parts.argb_dx[i].reg;
            int c = parts.argb[i].reg;
            dx = scratches.obtain();
            c = scratches.obtain();
            CONTEXT_LOAD(dx, generated_vars.argb[i].dx);
            CONTEXT_LOAD(c, generated_vars.argb[i].c);

            //if (reload & 1) {
            //    c = scratches.obtain();
            //    CONTEXT_LOAD(c, generated_vars.argb[i].c);
            //}
            //if (reload & 2) {
            //    dx = scratches.obtain();
            //    CONTEXT_LOAD(dx, generated_vars.argb[i].dx);
            //}

            if (mSmooth) {
                ADD_REG_TO_REG(dx, c);
            }

            CONTEXT_STORE(c, generated_vars.argb[i].c);
            scratches.recycle(c);
            scratches.recycle(dx);
            //if (reload & 1) {
            //    CONTEXT_STORE(c, generated_vars.argb[i].c);
            //    scratches.recycle(c);
            //}
            //if (reload & 2) {
            //    scratches.recycle(dx);
            //}
        }
        scratches.recycle(mBuilderContext.Rctx);
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_coverage_application(component_t& fragment,
        fragment_parts_t& parts, Scratch& regs)
{
    // here fragment.l is guarenteed to be 0
    if (mAA) {
        // coverages are 1.15 fixed-point numbers
        comment("coverage application");

        component_t incoming(fragment);
        modify(fragment, regs);

        Scratch scratches(registerFile());
        int cf = scratches.obtain();
        parts.covPtr.reg = scratches.obtain();
        MOV_MEM_TO_REG(parts.covPtr.offset_ebp, EBP, parts.covPtr.reg);
        MOVZX_MEM_TO_REG(OpndSize_16, parts.covPtr.reg, 2, cf); // refer to LDRH definition
        scratches.recycle(parts.covPtr.reg);
        if (fragment.h > 31) {
            fragment.h--;

            int flag_push_edx = 0;
            int flag_reserve_edx = 0;
            int temp_reg2 = -1;
            int edx_offset_ebp = 0;
            if(scratches.isUsed(EDX) == 1) {
                if(incoming.reg != EDX && cf != EDX) {
                    flag_push_edx = 1;
                    mCurSp = mCurSp - 4;
                    edx_offset_ebp = mCurSp;
                    MOV_REG_TO_MEM(EDX, edx_offset_ebp, EBP);
                }
            }
            else {
                flag_reserve_edx = 1;
                scratches.reserve(EDX);
            }
            if(scratches.isUsed(EAX)) {
                if( cf == EAX || incoming.reg == EAX) {
                    MOVSX_REG_TO_REG(OpndSize_16, cf, cf);
                    if(cf == EAX)
                        IMUL(incoming.reg);
                    else
                        IMUL(cf);
                    SHL(16, EDX);
                    SHR(16, EAX);
                    MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                    MOV_REG_TO_REG(EDX, incoming.reg);
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
                    }
                    MOV_REG_TO_REG(cf, EAX);
                    MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                    IMUL(incoming.reg);
                    SHL(16, EDX);
                    SHR(16, EAX);
                    MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                    MOV_REG_TO_REG(EDX, incoming.reg);
                    if(temp_reg2 > -1) {
                        MOV_REG_TO_REG(temp_reg2, EAX);
                        scratches.recycle(temp_reg2);
                    }
                    else {
                        MOV_MEM_TO_REG(eax_offset_ebp, EBP, EAX);
                    }
                }
            }
            else {
                MOV_REG_TO_REG(cf, EAX);
                MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                IMUL(incoming.reg);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, incoming.reg);
            }
            if(flag_push_edx == 1) {
                MOV_MEM_TO_REG(edx_offset_ebp, EBP, EDX);
            }
            if(flag_reserve_edx ==1)
                scratches.recycle(EDX);

            MOV_REG_TO_REG(incoming.reg, fragment.reg);

            //IMUL(cf, incoming.reg);
        } else {
            MOV_REG_TO_REG(incoming.reg, fragment.reg);
            SHL(1, fragment.reg);

            int flag_push_edx = 0;
            int flag_reserve_edx = 0;
            int temp_reg2 = -1;
            int edx_offset_ebp = 0;
            if(scratches.isUsed(EDX) == 1) {
                if(fragment.reg != EDX && cf != EDX) {
                    flag_push_edx = 1;
                    mCurSp = mCurSp - 4;
                    edx_offset_ebp = mCurSp;
                    MOV_REG_TO_MEM(EDX, edx_offset_ebp, EBP);
                }
            }
            else {
                flag_reserve_edx = 1;
                scratches.reserve(EDX);
            }
            if(scratches.isUsed(EAX)) {
                if( cf == EAX || fragment.reg == EAX) {
                    MOVSX_REG_TO_REG(OpndSize_16, cf, cf);
                    if(cf == EAX)
                        IMUL(fragment.reg);
                    else
                        IMUL(cf);
                    SHL(16, EDX);
                    SHR(16, EAX);
                    MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                    MOV_REG_TO_REG(EDX, fragment.reg);
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
                    }
                    MOV_REG_TO_REG(cf, EAX);
                    MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                    IMUL(fragment.reg);
                    SHL(16, EDX);
                    SHR(16, EAX);
                    MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                    MOV_REG_TO_REG(EDX, fragment.reg);
                    if(temp_reg2 > -1) {
                        MOV_REG_TO_REG(temp_reg2, EAX);
                        scratches.recycle(temp_reg2);
                    }
                    else {
                        MOV_MEM_TO_REG(eax_offset_ebp, EBP, EAX);
                    }
                }
            }
            else {
                MOV_REG_TO_REG(cf, EAX);
                MOVSX_REG_TO_REG(OpndSize_16, EAX, EAX);
                IMUL(fragment.reg);
                SHL(16, EDX);
                SHR(16, EAX);
                MOV_REG_TO_REG(EAX, EDX, OpndSize_16);
                MOV_REG_TO_REG(EDX, fragment.reg);
            }
            if(flag_push_edx == 1) {
                MOV_MEM_TO_REG(edx_offset_ebp, EBP, EDX);
            }
            if(flag_reserve_edx ==1)
                scratches.recycle(EDX);

            //IMUL(cf, fragment.reg);
        }
        scratches.recycle(cf);
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_alpha_test(component_t& fragment,
                                       const fragment_parts_t& parts)
{
    if (mAlphaTest != GGL_ALWAYS) {
        comment("Alpha Test");
        Scratch scratches(registerFile());
        int ref = scratches.obtain();
        mBuilderContext.Rctx  = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        const int shift = GGL_COLOR_BITS-fragment.size();
        CONTEXT_LOAD(ref, state.alpha_test.ref);
        scratches.recycle(mBuilderContext.Rctx);
        if (shift) {
            SHR(shift, ref);
            CMP_REG_TO_REG(ref, fragment.reg);
        } else   CMP_REG_TO_REG(ref, fragment.reg);
        Mnemonic cc = Mnemonic_NULL;
        //int cc = NV;
        switch (mAlphaTest) {
        case GGL_NEVER:
            JMP("discard_after_textures");
            return;
            break;
        case GGL_LESS:
            cc = Mnemonic_JNL;
            break;
        case GGL_EQUAL:
            cc = Mnemonic_JNE;
            break;
        case GGL_LEQUAL:
            cc = Mnemonic_JB;
            break;
        case GGL_GREATER:
            cc = Mnemonic_JLE;
            break;
        case GGL_NOTEQUAL:
            cc = Mnemonic_JE;
            break;
        case GGL_GEQUAL:
            cc = Mnemonic_JNC;
            break;
        }
        JCC(cc, "discard_after_textures");
        //B(cc^1, "discard_after_textures");
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_depth_test(
    const fragment_parts_t& parts, uint32_t mask)
{
    mask &= Z_TEST|Z_WRITE;
    int store_flag = 0;
    const needs_t& needs = mBuilderContext.needs;
    const int zmask = GGL_READ_NEEDS(P_MASK_Z, needs.p);
    Scratch scratches(registerFile());

    if (mDepthTest != GGL_ALWAYS || zmask) {
        Mnemonic ic = Mnemonic_NULL;
        switch (mDepthTest) {
        case GGL_LESS:
            ic = Mnemonic_JBE;
            break;
        case GGL_EQUAL:
            ic = Mnemonic_JNE;
            break;
        case GGL_LEQUAL:
            ic = Mnemonic_JB;
            break;
        case GGL_GREATER:
            ic = Mnemonic_JGE;
            break;
        case GGL_NOTEQUAL:
            ic = Mnemonic_JE;
            break;
        case GGL_GEQUAL:
            ic = Mnemonic_JA;
            break;
        case GGL_NEVER:
            // this never happens, because it's taken care of when
            // computing the needs. but we keep it for completness.
            comment("Depth Test (NEVER)");
            JMP("discard_before_textures");
            return;
        case GGL_ALWAYS:
            // we're here because zmask is enabled
            mask &= ~Z_TEST;    // test always passes.
            break;
        }


        if ((mask & Z_WRITE) && !zmask) {
            mask &= ~Z_WRITE;
        }

        if (!mask)
            return;

        comment("Depth Test");

        int zbase = scratches.obtain();
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        CONTEXT_LOAD(zbase, generated_vars.zbase);  // stall
        scratches.recycle(mBuilderContext.Rctx);

        int temp_reg1 = scratches.obtain();
        int depth = scratches.obtain();
        int z = parts.z.reg;
        MOV_MEM_TO_REG(parts.count.offset_ebp, PhysicalReg_EBP, temp_reg1);
        SHR(15, temp_reg1);
        SUB_REG_TO_REG(temp_reg1, zbase);

        // above does zbase = zbase + ((count >> 16) << 1)

        if (mask & Z_TEST) {
            MOVZX_MEM_TO_REG(OpndSize_16, zbase, 0, depth);
            MOV_MEM_TO_REG(parts.z.offset_ebp, PhysicalReg_EBP, temp_reg1);
            SHR(16, temp_reg1);
            CMP_REG_TO_REG(temp_reg1, depth);
            JCC(ic, "discard_before_textures");

        }
        if (mask & Z_WRITE) {
            if (mask == Z_WRITE) {
                // only z-write asked, cc is meaningless
                store_flag = 1;
            }
            // actually it must be stored since the above branch is not taken
            MOV_REG_TO_MEM(temp_reg1, 0, zbase, OpndSize_16);
        }
        scratches.recycle(temp_reg1);
        scratches.recycle(zbase);
        scratches.recycle(depth);
    }
}

void GGLX86Assembler::build_iterate_z(const fragment_parts_t& parts)
{
    const needs_t& needs = mBuilderContext.needs;
    if ((mDepthTest != GGL_ALWAYS) || GGL_READ_NEEDS(P_MASK_Z, needs.p)) {
        Scratch scratches(registerFile());
        int dzdx = scratches.obtain();
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        CONTEXT_LOAD(dzdx, generated_vars.dzdx);    // stall
        scratches.recycle(mBuilderContext.Rctx);
        ADD_REG_TO_MEM(dzdx, EBP, parts.z.offset_ebp);
        scratches.recycle(dzdx);
    }
}

void GGLX86Assembler::build_iterate_f(const fragment_parts_t& parts)
{
    const needs_t& needs = mBuilderContext.needs;
    if (GGL_READ_NEEDS(P_FOG, needs.p)) {
        Scratch scratches(registerFile());
        int dfdx = scratches.obtain();
        int f = scratches.obtain();
        mBuilderContext.Rctx = scratches.obtain();
        MOV_MEM_TO_REG(8, EBP, mBuilderContext.Rctx);
        CONTEXT_LOAD(f,     generated_vars.f);
        CONTEXT_LOAD(dfdx,  generated_vars.dfdx);   // stall
        ADD_REG_TO_REG(dfdx, f);
        CONTEXT_STORE(f,    generated_vars.f);
        scratches.recycle(mBuilderContext.Rctx);
        scratches.recycle(dfdx);
        scratches.recycle(f);
    }
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::build_logic_op(pixel_t& pixel, Scratch& regs)
{
    const needs_t& needs = mBuilderContext.needs;
    const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
    if (opcode == GGL_COPY)
        return;

    comment("logic operation");

    pixel_t s(pixel);
    if (!(pixel.flags & CORRUPTIBLE)) {
        pixel.reg = regs.obtain();
        pixel.flags |= CORRUPTIBLE;
    }

    pixel_t d(mDstPixel);
    d.reg = regs.obtain();
    MOV_MEM_TO_REG(mDstPixel.offset_ebp, EBP, d.reg);
    switch(opcode) {
    case GGL_CLEAR:
        MOV_IMM_TO_REG(0, pixel.reg);
        break;
    case GGL_AND:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        AND_REG_TO_REG(s.reg, pixel.reg);
        break;
    case GGL_AND_REVERSE:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        NOT(pixel.reg);
        AND_REG_TO_REG(s.reg, pixel.reg);
        break;
    case GGL_COPY:
        break;
    case GGL_AND_INVERTED:
        MOV_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        AND_REG_TO_REG(d.reg, pixel.reg);
        break;
    case GGL_NOOP:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        break;
    case GGL_XOR:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        XOR(s.reg, pixel.reg);
        break;
    case GGL_OR:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        OR_REG_TO_REG(s.reg, pixel.reg);
        break;
    case GGL_NOR:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        OR_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_EQUIV:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        XOR(s.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_INVERT:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_OR_REVERSE:    // s | ~d == ~(~s & d)
        MOV_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        AND_REG_TO_REG(d.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_COPY_INVERTED:
        MOV_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_OR_INVERTED:   // ~s | d == ~(s & ~d)
        MOV_REG_TO_REG(d.reg, pixel.reg);
        NOT(pixel.reg);
        AND_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_NAND:
        MOV_REG_TO_REG(d.reg, pixel.reg);
        AND_REG_TO_REG(s.reg, pixel.reg);
        NOT(pixel.reg);
        break;
    case GGL_SET:
        MOV_IMM_TO_REG(0, pixel.reg);
        NOT(pixel.reg);
        break;
    };
    regs.recycle(d.reg);
}

// ---------------------------------------------------------------------------


void GGLX86Assembler::build_and_immediate(int d, int s, uint32_t mask, int bits)
{
    uint32_t rot;
    uint32_t size = ((bits>=32) ? 0 : (1LU << bits)) - 1;
    mask &= size;

    if (mask == size) {
        if (d != s)
            MOV_REG_TO_REG(s, d);
        return;
    }

    MOV_REG_TO_REG(s, d);
    AND_IMM_TO_REG(mask, d);
}

void GGLX86Assembler::build_masking(pixel_t& pixel, Scratch& regs)
{
    if (!mMasking || mAllMasked) {
        return;
    }

    comment("color mask");

    pixel_t fb(mDstPixel);
    fb.reg = regs.obtain();
    MOV_MEM_TO_REG(mDstPixel.offset_ebp, EBP, fb.reg);
    pixel_t s(pixel);
    if (!(pixel.flags & CORRUPTIBLE)) {
        pixel.reg = regs.obtain();
        pixel.flags |= CORRUPTIBLE;
    }

    int mask = 0;
    for (int i=0 ; i<4 ; i++) {
        const int component_mask = 1<<i;
        const int h = fb.format.c[i].h;
        const int l = fb.format.c[i].l;
        if (h && (!(mMasking & component_mask))) {
            mask |= ((1<<(h-l))-1) << l;
        }
    }

    // There is no need to clear the masked components of the source
    // (unless we applied a logic op), because they're already zeroed
    // by construction (masked components are not computed)

    if (mLogicOp) {
        const needs_t& needs = mBuilderContext.needs;
        const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
        if (opcode != GGL_CLEAR) {
            // clear masked component of source
            build_and_immediate(pixel.reg, s.reg, mask, fb.size());
            s = pixel;
        }
    }

    // clear non masked components of destination
    build_and_immediate(fb.reg, fb.reg, ~mask, fb.size());

    // or back the channels that were masked
    if (s.reg == fb.reg) {
        // this is in fact a MOV
        if (s.reg == pixel.reg) {
            // ugh. this in in fact a nop
        } else {
            MOV_REG_TO_REG(fb.reg, pixel.reg);
        }
    } else {
        MOV_REG_TO_REG(fb.reg, pixel.reg);
        OR_REG_TO_REG(s.reg, pixel.reg);
    }
    MOV_REG_TO_MEM(fb.reg, mDstPixel.offset_ebp, EBP);
}

// ---------------------------------------------------------------------------

void GGLX86Assembler::base_offset(pointer_t& d, pointer_t& b, const reg_t& o)
{
// d and b are the same reference
    Scratch scratches(registerFile());
    int temp_reg = scratches.obtain();
    switch (b.size) {
    case 32:
        MOV_REG_TO_REG(b.reg, temp_reg);
        MOV_REG_TO_REG(o.reg, d.reg);
        SHL(2,d.reg);
        ADD_REG_TO_REG(temp_reg, d.reg);
        break;
    case 24:
        if (d.reg == b.reg) {
            MOV_REG_TO_REG(b.reg, temp_reg);
            MOV_REG_TO_REG(o.reg, d.reg);
            SHL(1,d.reg);
            ADD_REG_TO_REG(temp_reg, d.reg);
            ADD_REG_TO_REG(o.reg, d.reg);
        } else {
            MOV_REG_TO_REG(o.reg, temp_reg);
            SHL(1,temp_reg);
            MOV_REG_TO_REG(temp_reg, d.reg);
            ADD_REG_TO_REG(o.reg, d.reg);
            ADD_REG_TO_REG(b.reg, d.reg);
        }
        break;
    case 16:
        MOV_REG_TO_REG(b.reg, temp_reg);
        MOV_REG_TO_REG(o.reg, d.reg);
        SHL(1,d.reg);
        ADD_REG_TO_REG(temp_reg, d.reg);
        break;
    case 8:
        MOV_REG_TO_REG(b.reg, temp_reg);
        MOV_REG_TO_REG(o.reg, d.reg);
        ADD_REG_TO_REG(temp_reg, d.reg);
        break;
    }
    scratches.recycle(temp_reg);
}

// ----------------------------------------------------------------------------
// cheezy register allocator...
// ----------------------------------------------------------------------------

void X86RegisterAllocator::reset()
{
    mRegs.reset();
}

int X86RegisterAllocator::reserveReg(int reg)
{
    return mRegs.reserve(reg);
}

int X86RegisterAllocator::obtainReg()
{
    return mRegs.obtain();
}

void X86RegisterAllocator::recycleReg(int reg)
{
    mRegs.recycle(reg);
}

X86RegisterAllocator::RegisterFile& X86RegisterAllocator::registerFile()
{
    return mRegs;
}

// ----------------------------------------------------------------------------

X86RegisterAllocator::RegisterFile::RegisterFile()
    : mRegs(0), mTouched(0), mStatus(0)
{
    //reserve(PhysicalReg_EBP);
    //reserve(PhysicalReg_ESP);
}

X86RegisterAllocator::RegisterFile::RegisterFile(const RegisterFile& rhs)
    : mRegs(rhs.mRegs), mTouched(rhs.mTouched)
{
}

X86RegisterAllocator::RegisterFile::~RegisterFile()
{
}

bool X86RegisterAllocator::RegisterFile::operator == (const RegisterFile& rhs) const
{
    return (mRegs == rhs.mRegs);
}

void X86RegisterAllocator::RegisterFile::reset()
{
    mRegs = mTouched = mStatus = 0;
}

int X86RegisterAllocator::RegisterFile::reserve(int reg)
{
    LOG_ALWAYS_FATAL_IF(isUsed(reg),
                        "reserving register %d, but already in use",
                        reg);
    if(isUsed(reg)) return -1;
    mRegs |= (1<<reg);
    mTouched |= mRegs;
    return reg;
}

void X86RegisterAllocator::RegisterFile::reserveSeveral(uint32_t regMask)
{
    mRegs |= regMask;
    mTouched |= regMask;
}

int X86RegisterAllocator::RegisterFile::isUsed(int reg) const
{
    LOG_ALWAYS_FATAL_IF(reg>=6, "invalid register %d", reg);
    return mRegs & (1<<reg);
}

int X86RegisterAllocator::RegisterFile::obtain()
{
//multiplication result is in edx:eax
//ebx, ecx, edi, esi, eax, edx
    const char priorityList[6] = { PhysicalReg_EBX, PhysicalReg_ECX,PhysicalReg_EDI, PhysicalReg_ESI, PhysicalReg_EAX, PhysicalReg_EDX };

    const int nbreg = sizeof(priorityList);
    int i, r;
    for (i=0 ; i<nbreg ; i++) {
        r = priorityList[i];
        if (!isUsed(r)) {
            break;
        }
    }
    // this is not an error anymore because, we'll try again with
    // a lower optimization level.
    ALOGE_IF(i >= nbreg, "pixelflinger ran out of registers\n");
    if (i >= nbreg) {
        mStatus |= OUT_OF_REGISTERS;
        // we return SP so we can more easily debug things
        // the code will never be run anyway.
        printf("pixelflinger ran out of registers\n");
        return PhysicalReg_ESP;
        //return -1;
    }
    reserve(r);
    return r;
}

bool X86RegisterAllocator::RegisterFile::hasFreeRegs() const
{
    return ((mRegs & 0x3F) == 0x3F) ? false : true;
}

int X86RegisterAllocator::RegisterFile::countFreeRegs() const
{
    int f = ~mRegs & 0x3F;
    // now count number of 1
    f = (f & 0x5555) + ((f>>1) & 0x5555);
    f = (f & 0x3333) + ((f>>2) & 0x3333);
    f = (f & 0x0F0F) + ((f>>4) & 0x0F0F);
    f = (f & 0x00FF) + ((f>>8) & 0x00FF);
    return f;
}

void X86RegisterAllocator::RegisterFile::recycle(int reg)
{
    LOG_FATAL_IF(!isUsed(reg),
                 "recycling unallocated register %d",
                 reg);
    mRegs &= ~(1<<reg);
}

void X86RegisterAllocator::RegisterFile::recycleSeveral(uint32_t regMask)
{
    LOG_FATAL_IF((mRegs & regMask)!=regMask,
                 "recycling unallocated registers "
                 "(recycle=%08x, allocated=%08x, unallocated=%08x)",
                 regMask, mRegs, mRegs&regMask);
    mRegs &= ~regMask;
}

uint32_t X86RegisterAllocator::RegisterFile::touched() const
{
    return mTouched;
}

// ----------------------------------------------------------------------------

}; // namespace android
