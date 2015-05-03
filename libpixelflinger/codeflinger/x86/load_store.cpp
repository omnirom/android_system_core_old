/* libs/pixelflinger/codeflinger/x86/load_store.cpp
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
#include <stdio.h>
#include <cutils/log.h>

#include "codeflinger/x86/GGLX86Assembler.h"

namespace android {

// ----------------------------------------------------------------------------

void GGLX86Assembler::store(const pointer_t& addr, const pixel_t& s, uint32_t flags)
{
    const int bits = addr.size;
    const int inc = (flags & WRITE_BACK)?1:0;
    switch (bits) {
    case 32:
        if (inc) {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg);
            ADD_IMM_TO_REG(4, addr.reg);
        } else {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg);
        }
        break;
    case 24:
        // 24 bits formats are a little special and used only for RGB
        // 0x00BBGGRR is unpacked as R,G,B
        MOV_REG_TO_MEM(s.reg, 0, addr.reg, OpndSize_8);
        ROR(8, s.reg);
        MOV_REG_TO_MEM(s.reg, 1, addr.reg, OpndSize_8);
        ROR(8, s.reg);
        MOV_REG_TO_MEM(s.reg, 2, addr.reg, OpndSize_8);
        if (!(s.flags & CORRUPTIBLE)) {
            ROR(16, s.reg);
        }
        if (inc) {
            ADD_IMM_TO_REG(3, addr.reg);
        }
        break;
    case 16:
        if (inc) {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg,OpndSize_16);
            ADD_IMM_TO_REG(2, addr.reg);
        } else {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg,OpndSize_16);
        }
        break;
    case  8:
        if (inc) {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg,OpndSize_8);
            ADD_IMM_TO_REG(1, addr.reg);
        } else {
            MOV_REG_TO_MEM(s.reg, 0, addr.reg,OpndSize_8);
        }
        break;
    }
}

void GGLX86Assembler::load(pointer_t& addr, const pixel_t& s, uint32_t flags)
{
    Scratch scratches(registerFile());
    int s0;

    const int bits = addr.size;
    // WRITE_BACK indicates that the base register will also be updated after loading the data
    const int inc = (flags & WRITE_BACK)?1:0;
    switch (bits) {
    case 32:
        if (inc) {
            MOV_MEM_TO_REG(0, addr.reg, s.reg);
            ADD_IMM_TO_REG(4, addr.reg);

        } else        MOV_MEM_TO_REG(0, addr.reg, s.reg);
        break;
    case 24:
        // 24 bits formats are a little special and used only for RGB
        // R,G,B is packed as 0x00BBGGRR
        s0 = scratches.obtain();
        if (s.reg != addr.reg) {
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 0, s.reg); //R
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 1, s0);   //G
            SHL(8, s0);
            OR_REG_TO_REG(s0, s.reg);
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 2, s0); //B
            SHL(16, s0);
            OR_REG_TO_REG(s0, s.reg);
        } else {
            int s1 = scratches.obtain();
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 0, s1); //R
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 1, s0); //G
            SHL(8, s0);
            OR_REG_TO_REG(s0, s1);
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 2, s0); //B
            SHL(16, s0);
            OR_REG_TO_REG(s0, s1);
            MOV_REG_TO_REG(s1, s.reg);
            scratches.recycle(s1);

        }
        scratches.recycle(s0);
        if (inc)
            ADD_IMM_TO_REG(3, addr.reg);
        break;
    case 16:
        if (inc) {
            MOVZX_MEM_TO_REG(OpndSize_16, addr.reg, 0, s.reg);
            ADD_IMM_TO_REG(2, addr.reg);
        }
        else  MOVZX_MEM_TO_REG(OpndSize_16, addr.reg, 0, s.reg);
        break;
    case  8:
        if (inc) {
            MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 0, s.reg);
            ADD_IMM_TO_REG(1, addr.reg);
        }
        else        MOVZX_MEM_TO_REG(OpndSize_8, addr.reg, 0, s.reg);
        break;
    }
    if (inc) MOV_REG_TO_MEM(addr.reg, addr.offset_ebp, PhysicalReg_EBP);
}

void GGLX86Assembler::extract(integer_t& d, int s, int h, int l, int bits)
{
    const int maskLen = h-l;

    assert(maskLen<=8);
    assert(h);


    if (h != bits) {
        const int mask = ((1<<maskLen)-1) << l;
        MOV_REG_TO_REG(s, d.reg);
        AND_IMM_TO_REG(mask, d.reg);// component = packed & mask;
        s = d.reg;
    }

    if (l) {
        MOV_REG_TO_REG(s, d.reg);
        SHR(l, d.reg);// component = packed >> l;
        s = d.reg;
    }

    if (s != d.reg) {
        MOV_REG_TO_REG(s, d.reg);
    }

    d.s = maskLen;
}

void GGLX86Assembler::extract(integer_t& d, const pixel_t& s, int component)
{
    extract(d,  s.reg,
            s.format.c[component].h,
            s.format.c[component].l,
            s.size());
}

void GGLX86Assembler::extract(component_t& d, const pixel_t& s, int component)
{
    integer_t r(d.reg, 32, d.flags, d.offset_ebp);
    extract(r,  s.reg,
            s.format.c[component].h,
            s.format.c[component].l,
            s.size());
    d = component_t(r);
}


void GGLX86Assembler::expand(integer_t& d, const component_t& s, int dbits)
{
    if (s.l || (s.flags & CLEAR_HI)) {
        extract(d, s.reg, s.h, s.l, 32);
        expand(d, d, dbits);
    } else {
        expand(d, integer_t(s.reg, s.size(), s.flags, s.offset_ebp), dbits);
    }
}

void GGLX86Assembler::expand(component_t& d, const component_t& s, int dbits)
{
    integer_t r(d.reg, 32, d.flags, d.offset_ebp);
    expand(r, s, dbits);
    d = component_t(r);
}

void GGLX86Assembler::expand(integer_t& dst, const integer_t& src, int dbits)
{
    assert(src.size());

    Scratch scratches(registerFile());
    int sbits = src.size();
    int s = src.reg;
    int d = dst.reg;

    // be sure to set 'dst' after we read 'src' as they may be identical
    dst.s = dbits;
    dst.flags = 0;

    if (dbits<=sbits) {
        if (s != d) {
            MOV_REG_TO_REG(s, d);
        }
        return;
    }

    if (sbits == 1) {
        MOV_REG_TO_REG(s, d);
        SHL(dbits, d);
        SUB_REG_TO_REG(s, d);
        // d = (s<<dbits) - s;
        return;
    }

    if (dbits % sbits) {
        MOV_REG_TO_REG(s, d);
        SHL(dbits-sbits, d);
        // d = s << (dbits-sbits);
        dbits -= sbits;
        int temp = scratches.obtain();
        do {
            MOV_REG_TO_REG(d, temp);
            SHR(sbits, temp);
            OR_REG_TO_REG(temp, d);
            // d |= d >> sbits;
            dbits -= sbits;
            sbits *= 2;
        } while(dbits>0);
        return;
    }

    dbits -= sbits;
    do {
        MOV_REG_TO_REG(s, d);
        SHL(sbits, d);
        OR_REG_TO_REG(s, d);
        // d |= d<<sbits;
        s = d;
        dbits -= sbits;
        if (sbits*2 < dbits) {
            sbits *= 2;
        }
    } while(dbits>0);
}

void GGLX86Assembler::downshift(
    pixel_t& d, int component, component_t s, reg_t& dither)
{
    const needs_t& needs = mBuilderContext.needs;
    Scratch scratches(registerFile());
    // s(temp) is loaded in build_blending
    s.reg = scratches.obtain();
    MOV_MEM_TO_REG(s.offset_ebp, EBP, s.reg);

    int sh = s.h;
    int sl = s.l;
    int maskHiBits = (sh!=32) ? ((s.flags & CLEAR_HI)?1:0) : 0;
    int maskLoBits = (sl!=0)  ? ((s.flags & CLEAR_LO)?1:0) : 0;
    int sbits = sh - sl;

    int dh = d.format.c[component].h;
    int dl = d.format.c[component].l;
    int dbits = dh - dl;
    int dithering = 0;

    ALOGE_IF(sbits<dbits, "sbits (%d) < dbits (%d) in downshift", sbits, dbits);

    if (sbits>dbits) {
        // see if we need to dither
        dithering = mDithering;
    }

    int ireg = d.reg;
    if (!(d.flags & FIRST)) {
        if (s.flags & CORRUPTIBLE)  {
            ireg = s.reg;
        } else {
            ireg = scratches.obtain();
        }
    }
    d.flags &= ~FIRST;

    if (maskHiBits) {
        // we need to mask the high bits (and possibly the lowbits too)
        // and we might be able to use immediate mask.
        if (!dithering) {
            // we don't do this if we only have maskLoBits because we can
            // do it more efficiently below (in the case where dl=0)
            const int offset = sh - dbits;
            if (dbits<=8 && offset >= 0) {
                const uint32_t mask = ((1<<dbits)-1) << offset;
                build_and_immediate(ireg, s.reg, mask, 32);
                s.reg = ireg;
                sl = offset;
                sbits = dbits;
                maskLoBits = maskHiBits = 0;
            }
        } else {
            // in the dithering case though, we need to preserve the lower bits
            const uint32_t mask = ((1<<sbits)-1) << sl;
            build_and_immediate(ireg, s.reg, mask, 32);
            s.reg = ireg;
            maskLoBits = maskHiBits = 0;
        }
    }

    // XXX: we could special case (maskHiBits & !maskLoBits)
    // like we do for maskLoBits below, but it happens very rarely
    // that we have maskHiBits only and the conditions necessary to lead
    // to better code (like doing d |= s << 24)

    if (maskHiBits) {
        MOV_REG_TO_REG(s.reg, ireg);
        SHL(32-sh, ireg);
        sl += 32-sh;
        sh = 32;
        s.reg = ireg;
        maskHiBits = 0;
    }

    //  Downsampling should be performed as follows:
    //  V * ((1<<dbits)-1) / ((1<<sbits)-1)
    //  V * [(1<<dbits)/((1<<sbits)-1) - 1/((1<<sbits)-1)]
    //  V * [1/((1<<sbits)-1)>>dbits - 1/((1<<sbits)-1)]
    //  V/((1<<(sbits-dbits))-(1>>dbits)) - (V>>sbits)/((1<<sbits)-1)>>sbits
    //  V/((1<<(sbits-dbits))-(1>>dbits)) - (V>>sbits)/(1-(1>>sbits))
    //
    //  By approximating (1>>dbits) and (1>>sbits) to 0:
    //
    //  V>>(sbits-dbits) - V>>sbits
    //
    //  A good approximation is V>>(sbits-dbits),
    //  but better one (needed for dithering) is:
    //
    //  (V>>(sbits-dbits)<<sbits - V)>>sbits
    //  (V<<dbits - V)>>sbits
    //  (V - V>>dbits)>>(sbits-dbits)

    // Dithering is done here
    if (dithering) {
        comment("dithering");
        if (sl) {
            MOV_REG_TO_REG(s.reg, ireg);
            SHR(sl, ireg);
            sh -= sl;
            sl = 0;
            s.reg = ireg;
        }
        // scaling (V-V>>dbits)
        int temp_reg = scratches.obtain();
        MOV_REG_TO_REG(s.reg, temp_reg);
        SHR(dbits, temp_reg);
        MOV_REG_TO_REG(s.reg, ireg);
        SUB_REG_TO_REG(temp_reg, ireg);
        scratches.recycle(temp_reg);
        const int shift = (GGL_DITHER_BITS - (sbits-dbits));
        dither.reg = scratches.obtain();
        MOV_MEM_TO_REG(dither.offset_ebp, EBP, dither.reg);
        if (shift>0)  {
            temp_reg = scratches.obtain();
            MOV_REG_TO_REG(dither.reg, temp_reg);
            SHR(shift, temp_reg);
            ADD_REG_TO_REG(temp_reg, ireg);
            scratches.recycle(temp_reg);
        }
        else if (shift<0) {
            temp_reg = scratches.obtain();
            MOV_REG_TO_REG(dither.reg, temp_reg);
            SHL(-shift, temp_reg);
            ADD_REG_TO_REG(temp_reg, ireg);
            scratches.recycle(temp_reg);
        }
        else {
            ADD_REG_TO_REG(dither.reg, ireg);
        }
        scratches.recycle(dither.reg);
        s.reg = ireg;
    }

    if ((maskLoBits|dithering) && (sh > dbits)) {
        int shift = sh-dbits;
        if (dl) {
            MOV_REG_TO_REG(s.reg, ireg);
            SHR(shift, ireg);
            if (ireg == d.reg) {
                MOV_REG_TO_REG(ireg, d.reg);
                SHL(dl, d.reg);
            } else {
                int temp_reg = scratches.obtain();
                MOV_REG_TO_REG(ireg, temp_reg);
                SHL(dl, temp_reg);
                OR_REG_TO_REG(temp_reg, d.reg);
                scratches.recycle(temp_reg);
            }
        } else {
            if (ireg == d.reg) {
                MOV_REG_TO_REG(s.reg, d.reg);
                SHR(shift, d.reg);
            } else {
                int temp_reg = scratches.obtain();
                MOV_REG_TO_REG(s.reg, temp_reg);
                SHR(shift, temp_reg);
                OR_REG_TO_REG(temp_reg, d.reg);
                scratches.recycle(temp_reg);
            }
        }
    } else {
        int shift = sh-dh;
        if (shift>0) {
            if (ireg == d.reg) {
                MOV_REG_TO_REG(s.reg, d.reg);
                SHR(shift, d.reg);
            } else {
                int temp_reg = scratches.obtain();
                MOV_REG_TO_REG(s.reg, temp_reg);
                SHR(shift, temp_reg);
                OR_REG_TO_REG(temp_reg, d.reg);
                scratches.recycle(temp_reg);
            }
        } else if (shift<0) {
            if (ireg == d.reg) {
                MOV_REG_TO_REG(s.reg, d.reg);
                SHL(-shift, d.reg);
            } else {
                int temp_reg = scratches.obtain();
                MOV_REG_TO_REG(s.reg, temp_reg);
                SHL(-shift, temp_reg);
                OR_REG_TO_REG(temp_reg, d.reg);
                scratches.recycle(temp_reg);
            }
        } else {
            if (ireg == d.reg) {
                if (s.reg != d.reg) {
                    MOV_REG_TO_REG(s.reg, d.reg);
                }
            } else {
                OR_REG_TO_REG(s.reg, d.reg);
            }
        }
    }
}

}; // namespace android
