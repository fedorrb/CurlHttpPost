/* Begin FHbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource header file SERVERADDR.XME
//-------------------------------------------------------------------------
// Created 26\10\2019 16:00
//-------------------------------------------------------------------------

/* End FHbegin */
/* Begin FHhead */
#ifndef _SERVERADDR_H_
#define _SERVERADDR_H_

#include "staypic.h"
HPICMODULEBEG(SERVERADDR)

/* End FHhead */
/* Begin FHdefine */
/* End FHdefine */
/* Begin FHtypedef */
/* End FHtypedef */
/* Begin FHfield */
extern char J_SRVIP[16];
extern StayFD *_J_SRVIP;
extern StayFD _n_J_SRVIP;

extern char J_SRVPORT[6];
extern StayFD *_J_SRVPORT;
extern StayFD _n_J_SRVPORT;

extern BYTE  J_SRVDL;
extern StayFD *_J_SRVDL;
extern StayFD _n_J_SRVDL;

extern BYTE  J_SRVAT;
extern StayFD *_J_SRVAT;
extern StayFD _n_J_SRVAT;

extern BYTE  J_SRVType;
extern StayFD *_J_SRVType;
extern StayFD _n_J_SRVType;

/* End FHfield */
/* Begin FHdataset */
extern StayDataset _n_B_SvrAdr;
extern StayDataset *B_SvrAdr;
/* End FHdataset */
/* Begin FHmenu */
/* End FHmenu */
/* Begin FHframe */
/* End FHframe */
/* Begin FHtabl */
extern void *SERVERADDR[];
/* End FHtabl */
/* Begin FDfield */
/* End FDfield */
/* Begin FDextern */
/* End FDextern */
/* Begin FHend */

HPICMODULEEND(SERVERADDR)

#endif
/* End FHend */
