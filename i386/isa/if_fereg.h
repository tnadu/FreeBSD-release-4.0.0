/*
 * Hardware specification of various 8696x based Ethernet cards.
 * Contributed by M. Sekiguchi <seki@sysrap.cs.fujitsu.co.jp>
 *
 * All Rights Reserved, Copyright (C) Fujitsu Limited 1995
 *
 * This software may be used, modified, copied, distributed, and sold,
 * in both source and binary form provided that the above copyright,
 * these terms and the following disclaimer are retained.  The name of
 * the author and/or the contributor may not be used to endorse or
 * promote products derived from this software without specific prior
 * written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND THE CONTRIBUTOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR THE CONTRIBUTOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $FreeBSD: src/sys/i386/isa/if_fereg.h,v 1.7 1999/08/28 00:44:46 peter Exp $ */

/*
 * Registers on FMV-180 series' ISA bus interface ASIC.
 * I'm not sure the following register names are appropriate.
 * Doesn't it look silly, eh?  FIXME.
 */

#define FE_FMV0		16	/* Card status register #0	*/
#define FE_FMV1		17	/* Card status register #1	*/
#define FE_FMV2		18	/* Card config register #0	*/
#define FE_FMV3		19	/* Card config register #1	*/
#define FE_FMV4		20	/* Station address #1		*/
#define FE_FMV5		21	/* Station address #2		*/
#define FE_FMV6		22	/* Station address #3		*/
#define FE_FMV7		23	/* Station address #4		*/
#define FE_FMV8		24	/* Station address #5		*/
#define FE_FMV9		25	/* Station address #6		*/
#define FE_FMV10	26	/* Buffer RAM control register	*/
#define FE_FMV11	27	/* Buffer RAM data register	*/

/*
 * FMV-180 series' ASIC register values.
 */

/* FMV0: Card status register #0: Misc info?  */
#define FE_FMV0_MEDIA	0x07	/* Supported physical media.	*/
#define FE_FMV0_PRRDY	0x10	/* ???				*/
#define FE_FMV0_PRERR	0x20	/* ???				*/
#define FE_FMV0_ERRDY	0x40	/* ???				*/
#define FE_FMV0_IREQ	0x80	/* ???				*/

#define FE_FMV0_MEDIUM_5	0x01	/* 10base5/Dsub		*/
#define FE_FMV0_MEDIUM_2	0x02	/* 10base2/BNC		*/
#define FE_FMV0_MEDIUM_T	0x04	/* 10baseT/RJ45		*/

/* Card status register #1: Hardware revision.  */
#define FE_FMV1_REV	0x0F	/* Card revision		*/
#define FE_FMV1_UPPER	0xF0	/* Usage unknown		*/

/* Card config register #0: I/O port address assignment.  */
#define FE_FMV2_IOS	0x07	/* I/O selection.		*/
#define FE_FMV2_MES	0x38	/* ??? boot ROM?		*/
#define FE_FMV2_IRS	0xC0	/* IRQ selection.		*/

#define FE_FMV2_IOS_SHIFT	0
#define FE_FMV2_MES_SHIFT	3
#define FE_FMV2_IRS_SHIFT	6

/* Card config register #1: IRQ enable  */
#define FE_FMV3_IRQENB	0x80	/* IRQ enable.			*/

/*
 * Register(?) specific to AT1700/RE2000.
 */

#define FE_ATI_RESET	0x1F	/* Write to reset the 86965.	*/

/* EEPROM allocation (offsets) of AT1700/RE2000.  */
#define FE_ATI_EEP_ADDR		0x08	/* Station address.  (8-13)	*/
#define	FE_ATI_EEP_MEDIA	0x18	/* Media type.			*/
#define	FE_ATI_EEP_MAGIC	0x19	/* XXX Magic.			*/
#define FE_ATI_EEP_MODEL	0x1e	/* Hardware type.		*/
#define	FE_ATI_EEP_REVISION	0x1f	/* Hardware revision.		*/

/* Value for FE_ATI_EEP_MODEL.  */
#define FE_ATI_MODEL_AT1700T	0x00
#define FE_ATI_MODEL_AT1700BT	0x01
#define FE_ATI_MODEL_AT1700FT	0x02
#define FE_ATI_MODEL_AT1700AT	0x03

/*
 * Registers on MBH10302.
 */

#define FE_MBH0		0x10	/* ???  Including interrupt.	*/
#define FE_MBH1		0x11	/* ???				*/
#define FE_MBH10	0x1A	/* Station address.  (10 - 15)	*/

/* Values to be set in MBH0 register.  */
#define FE_MBH0_MAGIC	0x0D	/* Just a magic constant?	*/
#define FE_MBH0_INTR	0x10	/* Master interrupt control.	*/

#define FE_MBH0_INTR_ENABLE	0x10	/* Enable interrupts.	*/
#define FE_MBH0_INTR_DISABLE	0x00	/* Disable interrupts.	*/

/*
 * Registers on RE1000.  (*NOT* on RE1000 Plus.)
 */

/* IRQ configuration.  */
#define	FE_RE1000_IRQCONF	0x10
