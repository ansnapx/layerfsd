/*
	R_RANDOM.H - header file for R_RANDOM.C

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
        direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Random Number Routines Header File.

	Revision 1.00 - JSAK.
*/

#ifndef _R_RANDOM_H_
#define _R_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

int __stdcall R_GenerateBytes
  (unsigned char *, unsigned int, R_RANDOM_STRUCT *);

#ifdef __cplusplus
}
#endif

#endif//_R_RANDOM_H_