/*
 *  Copyright (C) 1994 Geoffrey M. Rehmet
 *
 *  This program is free software; you may redistribute it and/or
 *  modify it, provided that it retain the above copyright notice
 *  and the following disclaimer.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	Geoff Rehmet, Rhodes University, South Africa <csgr@cs.ru.ac.za>
 *
 * $FreeBSD: src/sys/i386/include/lpt.h,v 1.7 1999/08/28 00:44:18 peter Exp $
 */

#ifndef	_MACHINE_LPT_H_
#define	_MACHINE_LPT_H_

#include <sys/ioccom.h>

#define	LPT_IRQ		_IOW('p', 1, long)	/* set interrupt status */

#endif /* !_MACHINE_LPT_H_ */
