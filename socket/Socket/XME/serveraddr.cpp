/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file SERVERADDR.XME
//-------------------------------------------------------------------------
// Created 26\10\2019 16:00
//-------------------------------------------------------------------------

#include "SERVERADDR.h"

/* End FCbegin */
/* Begin FCinclude */
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(SERVERADDR)

static StayFD _nn_SERVERADDR = {NULL,TAG_PIC,0,0,0,0,"SERVERADDR",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
char J_SRVIP[16];
StayFD _n_J_SRVIP = {&J_SRVIP,0,0,0,CLS_V,15,"J_SRVIP","ip адреса сервера"};
StayFD *_J_SRVIP = &_n_J_SRVIP;

char J_SRVPORT[6];
StayFD _n_J_SRVPORT = {&J_SRVPORT,0,0,0,CLS_V,5,"J_SRVPORT","порт сервера"};
StayFD *_J_SRVPORT = &_n_J_SRVPORT;

BYTE  J_SRVDL;
StayFD _n_J_SRVDL = {&J_SRVDL,0,0,0,CLS_S,0,"J_SRVDL","Затримка на шатдаун сокета сек"};
StayFD *_J_SRVDL = &_n_J_SRVDL;

BYTE  J_SRVAT;
StayFD _n_J_SRVAT = {&J_SRVAT,0,0,0,CLS_S,0,"J_SRVAT","Кількість спроб читати відповідь"};
StayFD *_J_SRVAT = &_n_J_SRVAT;

BYTE  J_SRVType;
StayFD _n_J_SRVType = {&J_SRVType,0,0,0,CLS_S,0,"J_SRVType",""};
StayFD *_J_SRVType = &_n_J_SRVType;

/* End FCfield */
/* Begin FCextern */
extern StayDataset _n_B_SvrAdr;
/* End FCextern */
/* Begin FCdataset */
static StayFD *tcm_B_SvrAdr[] =
{
 (StayFD *)&_n_J_SRVIP,
 (StayFD *)&_n_J_SRVPORT,
 (StayFD *)&_n_J_SRVDL,
 (StayFD *)&_n_J_SRVAT,
 (StayFD *)&_n_J_SRVType,
 NULL
};
StayDataset _n_B_SvrAdr = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_SvrAdr,NULL,
"SOK:srvradrs.DT",NULL,NULL,"B_SvrAdr",0};
StayDataset *B_SvrAdr = &_n_B_SvrAdr;

/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */
/* End FCframe */
/* Begin FCtabl */
void *SERVERADDR[] =
 {NULL,
  &_nn_SERVERADDR,
  &_n_J_SRVIP,
  &_n_J_SRVPORT,
  &_n_J_SRVDL,
  &_n_J_SRVAT,
  &_n_J_SRVType,
  (StayFD *)B_SvrAdr,
  NULL};

PICMODULEEND(SERVERADDR)

/* End FCtabl */
/* Begin FTfield */
/* End FTfield */
/* Begin FTdataset */
/* End FTdataset */
/* Begin FTtcm */
/* End FTtcm */
/* Begin FTframe */
/* End FTframe */
/* Begin FTtabl */
/* End FTtabl */
/* Begin FCmmm */
/* End FCmmm */
/* Begin FMfield */
/* End FMfield */
/* Begin FMdataset */
/* End FMdataset */
/* Begin FMframe */
/* End FMframe */
/* Begin FMend */
/* End FMend */
/* Begin FTend */
/* End FTend */
/* Begin FCend */
/* End FCend */
