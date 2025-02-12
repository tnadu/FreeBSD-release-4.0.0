/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (augustss@carlstedt.se) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/pci/uhci_pci.c,v 1.26 2000/02/20 14:22:44 n_hibma Exp $
 */

/* Universal Host Controller Interface
 *
 * UHCI spec: http://www.intel.com/
 */

/* The low level controller code for UHCI has been split into
 * PCI probes and UHCI specific code. This was done to facilitate the
 * sharing of code between *BSD's
 */

#include "opt_bus.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/queue.h>
#if defined(__FreeBSD__)
#include <sys/bus.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>
#endif

#include <pci/pcivar.h>
#include <pci/pcireg.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usb_mem.h>

#include <dev/usb/uhcireg.h>
#include <dev/usb/uhcivar.h>

#define PCI_UHCI_VENDORID_INTEL		0x8086
#define PCI_UHCI_VENDORID_VIA		0x1106

#define PCI_UHCI_DEVICEID_PIIX3         0x70208086
static const char *uhci_device_piix3	= "Intel 82371SB (PIIX3) USB controller";
#define PCI_UHCI_DEVICEID_PIIX4         0x71128086
#define PCI_UHCI_DEVICEID_PIIX4E        0x71128086    /* no separate stepping */
static const char *uhci_device_piix4	= "Intel 82371AB/EB (PIIX4) USB controller";
#define PCI_UHCI_DEVICEID_ICH		0x24128086
static const char *uhci_device_ich	= "Intel 82801AA (ICH) USB controller";
#define PCI_UHCI_DEVICEID_ICH0		0x24228086
static const char *uhci_device_ich0 	= "Intel 82801AB (ICH0) USB controller";
#define PCI_UHCI_DEVICEID_VT83C572	0x30381106
static const char *uhci_device_vt83c572	= "VIA 83C572 USB controller";

static const char *uhci_device_generic	= "UHCI (generic) USB controller";

#define PCI_UHCI_BASE_REG               0x20

static int
uhci_pci_suspend(device_t self)
{
	uhci_softc_t *sc = device_get_softc(self);
	int err;

	err = bus_generic_suspend(self);
	if (err)
		return err;
	uhci_power(PWR_SUSPEND, sc);

	return 0;
}

static int
uhci_pci_resume(device_t self)
{
	uhci_softc_t *sc = device_get_softc(self);

	uhci_power(PWR_RESUME, sc);
	bus_generic_resume(self);

	return 0;
}

static const char *
uhci_pci_match(device_t self)
{
	u_int32_t device_id = pci_get_devid(self);

	if (device_id == PCI_UHCI_DEVICEID_PIIX3) {
		return (uhci_device_piix3);
	} else if (device_id == PCI_UHCI_DEVICEID_PIIX4) {
		return (uhci_device_piix4);
	} else if (device_id == PCI_UHCI_DEVICEID_ICH) {
		return (uhci_device_ich);
	} else if (device_id == PCI_UHCI_DEVICEID_ICH0) {
		return (uhci_device_ich0);
	} else if (device_id == PCI_UHCI_DEVICEID_VT83C572) {
		return (uhci_device_vt83c572);
	} else {
		if (   pci_get_class(self)    == PCIC_SERIALBUS
		    && pci_get_subclass(self) == PCIS_SERIALBUS_USB
		    && pci_get_progif(self)   == PCI_INTERFACE_UHCI) {
			return (uhci_device_generic);
		}
	}

	return NULL;    /* dunno... */
}

static int
uhci_pci_probe(device_t self)
{
	const char *desc = uhci_pci_match(self);
	if (desc) {
		device_set_desc(self, desc);
		return 0;
	} else {
		return ENXIO;
	}
}

static int
uhci_pci_attach(device_t self)
{
	uhci_softc_t *sc = device_get_softc(self);
	device_t parent = device_get_parent(self);
	int rid;
	void *ih;
	struct resource *io_res, *irq_res;
	int intr;
	int err;

	/* For the moment, put in a message stating what is wrong */
	intr = pci_read_config(self, PCIR_INTLINE, 1);
	if (intr == 0 || intr == 255) {
		device_printf(self, "Invalid irq %d\n", intr);
		device_printf(self, "Please switch on USB support and switch PNP-OS to 'No' in BIOS\n");
		return ENXIO;
	}

	rid = PCI_UHCI_BASE_REG;
	io_res = bus_alloc_resource(self, SYS_RES_IOPORT, &rid,
				    0, ~0, 1, RF_ACTIVE);
	if (!io_res) {
		device_printf(self, "could not map ports\n");
		return ENXIO;
        }

	sc->iot = rman_get_bustag(io_res);
	sc->ioh = rman_get_bushandle(io_res);

	/* disable interrupts */
	bus_space_write_2(sc->iot, sc->ioh, UHCI_INTR, 0);

	rid = 0;
	irq_res = bus_alloc_resource(self, SYS_RES_IRQ, &rid, 0, ~0, 1,
				     RF_SHAREABLE | RF_ACTIVE);
	if (irq_res == NULL) {
		device_printf(self, "could not allocate irq\n");
		err = ENOMEM;
		goto bad1;
	}
		
	sc->sc_bus.bdev = device_add_child(self, "usb", -1);
	if (!sc->sc_bus.bdev) {
		device_printf(self, "could not add USB device\n");
		err = ENOMEM;
		goto bad2;
	}
	device_set_ivars(sc->sc_bus.bdev, sc);

	switch (pci_get_devid(self)) {
	case PCI_UHCI_DEVICEID_PIIX3:
		device_set_desc(sc->sc_bus.bdev, uhci_device_piix3);
		sprintf(sc->sc_vendor, "Intel");
		break;
	case PCI_UHCI_DEVICEID_PIIX4:
		device_set_desc(sc->sc_bus.bdev, uhci_device_piix4);
		sprintf(sc->sc_vendor, "Intel");
		break;
	case PCI_UHCI_DEVICEID_ICH:
		device_set_desc(sc->sc_bus.bdev, uhci_device_ich);
		sprintf(sc->sc_vendor, "Intel");
		break;
	case PCI_UHCI_DEVICEID_ICH0:
		device_set_desc(sc->sc_bus.bdev, uhci_device_ich0);
		sprintf(sc->sc_vendor, "Intel");
		break;
	case PCI_UHCI_DEVICEID_VT83C572:
		device_set_desc(sc->sc_bus.bdev, uhci_device_vt83c572);
		sprintf(sc->sc_vendor, "VIA");
		break;
	default:
		device_printf(self, "(New UHCI DeviceId=0x%08x)\n",
			      pci_get_devid(self));
		device_set_desc(sc->sc_bus.bdev, uhci_device_generic);
		sprintf(sc->sc_vendor, "(0x%08x)", pci_get_devid(self));
	}

	switch(pci_read_config(self, PCI_USBREV, 4) & PCI_USBREV_MASK) {
	case PCI_USBREV_PRE_1_0:
		sc->sc_bus.usbrev = USBREV_PRE_1_0;
		break;
	case PCI_USBREV_1_0:
		sc->sc_bus.usbrev = USBREV_1_0;
		break;
	default:
		sc->sc_bus.usbrev = USBREV_UNKNOWN;
		break;
	}

	err = BUS_SETUP_INTR(parent, self, irq_res, INTR_TYPE_BIO,
			       (driver_intr_t *) uhci_intr, sc, &ih);
	if (err) {
		device_printf(self, "could not setup irq, %d\n", err);
		goto bad3;
	}

	/* Set the PIRQD enable bit and switch off all the others. We don't
	 * want legacy support to interfere with us
	 * XXX Does this also mean that the BIOS won't touch the keyboard
	 * anymore if it is connected to the ports of the root hub?
	 */
#ifdef UHCI_DEBUG
	if (pci_read_config(self, PCI_LEGSUP, 4) != PCI_LEGSUP_USBPIRQDEN)
		device_printf(self, "LegSup = 0x%08x\n",
			      pci_read_config(self, PCI_LEGSUP, 4));
#endif
	pci_write_config(self, PCI_LEGSUP, PCI_LEGSUP_USBPIRQDEN, 4);

	err = uhci_init(sc);
	if (!err)
		err = device_probe_and_attach(sc->sc_bus.bdev);

	if (err) {
		device_printf(self, "USB init failed\n");
		err = EIO;
		goto bad4;
	}

	return 0;

bad4:
	/* disable interrupts that might have been switched on
	 * in uhci_init.
	 */
	bus_space_write_2(sc->iot, sc->ioh, UHCI_INTR, 0);

	err = BUS_TEARDOWN_INTR(parent, self, irq_res, ih);
	if (err)
		/* XXX or should we panic? */
		device_printf(self, "could not tear down irq, %d\n",
			      err);

bad3:
	device_delete_child(self, sc->sc_bus.bdev);
bad2:
	bus_release_resource(self, SYS_RES_IRQ, 0, irq_res);
bad1:
	bus_release_resource(self, SYS_RES_IOPORT, PCI_UHCI_BASE_REG, io_res);
	return err;
}

static device_method_t uhci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		uhci_pci_probe),
	DEVMETHOD(device_attach,	uhci_pci_attach),
	DEVMETHOD(device_suspend,	uhci_pci_suspend),
	DEVMETHOD(device_resume,	uhci_pci_resume),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	bus_generic_print_child),

	{ 0, 0 }
};

static driver_t uhci_driver = {
	"uhci",
	uhci_methods,
	sizeof(uhci_softc_t),
};

static devclass_t uhci_devclass;

DRIVER_MODULE(uhci, pci, uhci_driver, uhci_devclass, 0, 0);
