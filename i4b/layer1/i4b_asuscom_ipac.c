/*
 * Copyright (c) 1999 Ari Suutari. All rights reserved.
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------
 *
 *	isic - I4B Siemens ISDN Chipset Driver for Asuscom ISDNlink 128K PnP
 *	=====================================================================
 *
 * 	This driver works with Asuscom ISDNlink 128K PnP ISA adapter,
 * 	which is based on Siemens IPAC chip (my card probes as ASU1690).
 *	Older Asuscom ISA cards are based on different chipset
 *	(containing two chips) - for those cards, one might want
 *	to try the Dynalink driver.
 *
 *	This driver is heavily based on ELSA Quickstep 1000pro PCI
 *	driver written by Hellmuth Michaelis. Card initialization
 *	code is modeled after Linux i4l driver written by Karsten
 *	Keil.
 *
 *	$Id: i4b_asuscom_ipac.c,v 1.4 1999/12/13 21:25:26 hm Exp $
 *
 * $FreeBSD: src/sys/i4b/layer1/i4b_asuscom_ipac.c,v 1.4 1999/12/14 20:48:17 hm Exp $
 *
 *      last edit-date: [Mon Dec 13 21:58:27 1999]
 *
 *---------------------------------------------------------------------------*/

#include "isic.h"
#include "opt_i4b.h"

#if (NISIC > 0) && defined (ASUSCOM_IPAC)

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <machine/clock.h>

#include <net/if.h>

#include <machine/i4b_debug.h>
#include <machine/i4b_ioctl.h>

#include <i4b/include/i4b_global.h>
#include <i4b/include/i4b_l1l2.h>
#include <i4b/include/i4b_mbuf.h>

#include <i4b/layer1/i4b_l1.h>
#include <i4b/layer1/i4b_ipac.h>
#include <i4b/layer1/i4b_isac.h>
#include <i4b/layer1/i4b_hscx.h>

/* masks for register encoded in base addr */

#define ASI_BASE_MASK		0x0ffff
#define ASI_OFF_MASK		0xf0000

/* register id's to be encoded in base addr */

#define ASI_IDISAC		0x00000
#define ASI_IDHSCXA		0x10000
#define ASI_IDHSCXB		0x20000
#define ASI_IDIPAC		0x40000

/* offsets from base address */

#define ASI_OFF_ALE		0x00
#define ASI_OFF_RW		0x01

/*---------------------------------------------------------------------------*
 *      Asuscom ISDNlink 128K ISAC get fifo routine
 *---------------------------------------------------------------------------*/
static void 
asi_read_fifo(struct l1_softc *sc,int what,void *buf,size_t size)
{
	bus_space_tag_t    t = rman_get_bustag(sc->sc_resources.io_base[0]);
	bus_space_handle_t h = rman_get_bushandle(sc->sc_resources.io_base[0]);

	switch ( what )
	{
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_ISAC_OFF);
			bus_space_read_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_HSCXA_OFF);
			bus_space_read_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_HSCXB_OFF);
			bus_space_read_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
	}
}

/*---------------------------------------------------------------------------*
 *      Asuscom ISDNlink 128K ISAC put fifo routine
 *---------------------------------------------------------------------------*/
static void 
asi_write_fifo(struct l1_softc *sc,int what,void *buf,size_t size)
{
	bus_space_tag_t    t = rman_get_bustag(sc->sc_resources.io_base[0]);
	bus_space_handle_t h = rman_get_bushandle(sc->sc_resources.io_base[0]);

	switch ( what )
	{
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_ISAC_OFF);
			bus_space_write_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_HSCXA_OFF);
			bus_space_write_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t,h,ASI_OFF_ALE,IPAC_HSCXB_OFF);
			bus_space_write_multi_1(t,h,ASI_OFF_RW,buf,size);
			break;
	}
}

/*---------------------------------------------------------------------------*
 *      Asuscom ISDNlink 128K ISAC put register routine
 *---------------------------------------------------------------------------*/
static void
asi_write_reg(struct l1_softc *sc,int what,bus_size_t reg,u_int8_t data)
{
	bus_space_tag_t    t = rman_get_bustag(sc->sc_resources.io_base[0]);
	bus_space_handle_t h = rman_get_bushandle(sc->sc_resources.io_base[0]);

	switch ( what )
	{
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_ISAC_OFF);
			bus_space_write_1(t,h,ASI_OFF_RW,data);
			break;
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_HSCXA_OFF);
			bus_space_write_1(t,h,ASI_OFF_RW,data);
			break;
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_HSCXB_OFF);
			bus_space_write_1(t,h,ASI_OFF_RW,data);
			break;
		case ISIC_WHAT_IPAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_IPAC_OFF);
			bus_space_write_1(t,h,ASI_OFF_RW,data);
			break;
	}
}

/*---------------------------------------------------------------------------*
 *	Asuscom ISDNlink 128K ISAC get register routine
 *---------------------------------------------------------------------------*/
static u_int8_t
asi_read_reg(struct l1_softc *sc,int what,bus_size_t reg)
{
	bus_space_tag_t    t = rman_get_bustag(sc->sc_resources.io_base[0]);
	bus_space_handle_t h = rman_get_bushandle(sc->sc_resources.io_base[0]);

	switch ( what )
	{
		case ISIC_WHAT_ISAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_ISAC_OFF);
			return bus_space_read_1(t,h,ASI_OFF_RW);
		case ISIC_WHAT_HSCXA:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_HSCXA_OFF);
			return bus_space_read_1(t,h,ASI_OFF_RW);
		case ISIC_WHAT_HSCXB:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_HSCXB_OFF);
			return bus_space_read_1(t,h,ASI_OFF_RW);
		case ISIC_WHAT_IPAC:
			bus_space_write_1(t,h,ASI_OFF_ALE,reg+IPAC_IPAC_OFF);
			return bus_space_read_1(t,h,ASI_OFF_RW);
		default:
			return 0;
	}
}

/*---------------------------------------------------------------------------*
 *	isic_attach_siemens_isurf - attach for Asuscom ISDNlink 128K
 *---------------------------------------------------------------------------*/
int
isic_attach_asi(device_t dev)
{
	int unit = device_get_unit(dev);
	struct l1_softc *sc = &l1_sc[unit];	
	
	/* setup access routines */

	sc->clearirq = NULL;
	sc->readreg = asi_read_reg;
	sc->writereg = asi_write_reg;

	sc->readfifo = asi_read_fifo;
	sc->writefifo = asi_write_fifo;

	/* setup card type */
	
	sc->sc_cardtyp = CARD_TYPEP_ASUSCOMIPAC;

	/* setup IOM bus type */
	
	sc->sc_bustyp = BUS_TYPE_IOM2;

	/* setup chip type = IPAC ! */
	
	sc->sc_ipac = 1;
	sc->sc_bfifolen = IPAC_BFIFO_LEN;

	/* enable hscx/isac irq's */
/*
 * This has been taken from Linux driver.
 * (Removed initialization that was not applicaple to
 * this board or was already register default setting.)
 */
	IPAC_WRITE (IPAC_ACFG, 0xff);	/* Setup AUX pin modes		*/
	IPAC_WRITE (IPAC_AOE, 0x0);	/* Setup AUX pin modes		*/
	IPAC_WRITE (IPAC_MASK, (IPAC_MASK_INT1 | IPAC_MASK_INT0));

	return(0);
}
#endif /* (NISIC > 0) && defined (ASUSCOM_IPAC) */
