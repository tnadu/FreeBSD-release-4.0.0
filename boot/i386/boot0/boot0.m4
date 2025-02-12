#
# Copyright (c) 1998 Robert Nordier
# All rights reserved.
#
# Redistribution and use in source and binary forms are freely
# permitted provided that the above copyright notice and this
# paragraph and the following disclaimer are duplicated in all
# such forms.
#
# This software is provided "AS IS" and without any express or
# implied warranties, including, without limitation, the implied
# warranties of merchantability and fitness for a particular
# purpose.
#

# $FreeBSD: src/sys/boot/i386/boot0/boot0.m4,v 1.5 1999/08/28 00:39:59 peter Exp $

define(_al,0x0)dnl
define(_cl,0x1)dnl
define(_dl,0x2)dnl
define(_bl,0x3)dnl
define(_ah,0x4)dnl
define(_ch,0x5)dnl
define(_dh,0x6)dnl
define(_bh,0x7)dnl

define(_ax,0x0)dnl
define(_cx,0x1)dnl
define(_dx,0x2)dnl
define(_bx,0x3)dnl
define(_sp,0x4)dnl
define(_bp,0x5)dnl
define(_si,0x6)dnl
define(_di,0x7)dnl

define(_es,0x0)dnl
define(_cs,0x1)dnl
define(_ss,0x2)dnl
define(_ds,0x3)dnl
define(_fs,0x4)dnl
define(_gs,0x5)dnl

define(_bx_si,0x0)dnl
define(_bx_di,0x1)dnl
define(_bp_si,0x2)dnl
define(_bp_di,0x3)dnl
define(_si_,0x4)dnl
define(_di_,0x5)dnl
define(_bp_,0x6)dnl
define(_bx_,0x7)dnl

define(o16,`.byte 0x66')dnl

define(addw1r,`.byte 0x3; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(addwia,`.byte 0x5; .word $1')dnl
define(btwr1,`.word 0xa30f; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(btswr1,`.word 0xab0f; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(cmpbmr,`.byte 0x3a; .byte 0x6 | ($2 << 0x3); .word $1')dnl
define(cmpw1r,`.byte 0x3b; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(cmpwi2,`.byte 0x81; .byte 0xb8 | $3; .word $2; .word $1')dnl
define(addwir,`.byte 0x83; .byte 0xc0 | $2; .byte $1')dnl
define(movbr0,`.byte 0x88; .byte ($1 << 0x3) | $2')dnl
define(movbr1,`.byte 0x88; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(movwr1,`.byte 0x89; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(movb0r,`.byte 0x8a; .byte ($2 << 0x3) | $1')dnl
define(addb0r,`.byte 0x2; .byte ($2 << 0x3) | $1')dnl
define(movb1r,`.byte 0x8a; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(movw1r,`.byte 0x8b; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(movws1,`.byte 0x8c; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(movwir,`.byte 0xb8 | $2; .word $1')dnl
define(movbi0,`.byte 0xc6; .byte $2; .byte $1')dnl
define(callwi,`.byte 0xe8; .word $1 - . - 0x2')dnl
define(jmpnwi,`.byte 0xe9; .word $1 - . - 0x2')dnl
define(tstbi1,`.byte 0xf6; .byte 0x40 | $3; .byte $2; .byte $1')dnl
define(incb1,`.byte 0xfe; .byte 0x40 | $2; .byte $1')dnl
define(pushw1,`.byte 0xff; .byte 0x70 | $2; .byte $1')dnl
