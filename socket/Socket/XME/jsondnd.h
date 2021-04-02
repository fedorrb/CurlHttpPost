/* Begin FHbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource header file JSONDND.XME
//-------------------------------------------------------------------------
// Created 22\08\2018 16:39
//-------------------------------------------------------------------------

/* End FHbegin */
/* Begin FHhead */
#ifndef _JSONDND_H_
#define _JSONDND_H_

#include "staypic.h"
HPICMODULEBEG(JSONDND)

/* End FHhead */
/* Begin FHdefine */
/* End FHdefine */
/* Begin FHtypedef */
/* End FHtypedef */
/* Begin FHfield */
extern BYTE  RQ_Ver;
extern StayFD *_RQ_Ver;
extern StayFD _n_RQ_Ver;

extern WORD  RQ_State;
extern StayFD *_RQ_State;
extern StayFD _n_RQ_State;

extern DWORD RQ_Ident;
extern StayFD *_RQ_Ident;
extern StayFD _n_RQ_Ident;

extern DWORD RQ_Nls;
extern StayFD *_RQ_Nls;
extern StayFD _n_RQ_Nls;

extern WORD  RQ_Raj;
extern StayFD *_RQ_Raj;
extern StayFD _n_RQ_Raj;

extern char RQ_PrntSName[26];
extern StayFD *_RQ_PrntSName;
extern StayFD _n_RQ_PrntSName;

extern char RQ_PrntMName[26];
extern StayFD *_RQ_PrntMName;
extern StayFD _n_RQ_PrntMName;

extern char RQ_PrntLName[26];
extern StayFD *_RQ_PrntLName;
extern StayFD _n_RQ_PrntLName;

extern char RQ_PId[11];
extern StayFD *_RQ_PId;
extern StayFD _n_RQ_PId;

extern BYTE  RQ_PasspType;
extern StayFD *_RQ_PasspType;
extern StayFD _n_RQ_PasspType;

extern char RQ_PaspSN[16];
extern StayFD *_RQ_PaspSN;
extern StayFD _n_RQ_PaspSN;

extern StayDate RQ_PaspDt;
extern StayFD *_RQ_PaspDt;
extern StayFD _n_RQ_PaspDt;

extern StayDate RQ_BirthDtP;
extern StayFD *_RQ_BirthDtP;
extern StayFD _n_RQ_BirthDtP;

extern char RQ_ChldSName[26];
extern StayFD *_RQ_ChldSName;
extern StayFD _n_RQ_ChldSName;

extern char RQ_ChldMName[26];
extern StayFD *_RQ_ChldMName;
extern StayFD _n_RQ_ChldMName;

extern char RQ_ChldLName[26];
extern StayFD *_RQ_ChldLName;
extern StayFD _n_RQ_ChldLName;

extern StayDate RQ_BirthDtC;
extern StayFD *_RQ_BirthDtC;
extern StayFD _n_RQ_BirthDtC;

extern char RQ_SvidSN[26];
extern StayFD *_RQ_SvidSN;
extern StayFD _n_RQ_SvidSN;

extern StayDate RQ_SvidDt;
extern StayFD *_RQ_SvidDt;
extern StayFD _n_RQ_SvidDt;

extern WORD  RQ_Insp;
extern StayFD *_RQ_Insp;
extern StayFD _n_RQ_Insp;

extern char RQ_InspFio[51];
extern StayFD *_RQ_InspFio;
extern StayFD _n_RQ_InspFio;

extern StayDate RQ_CreateDt;
extern StayFD *_RQ_CreateDt;
extern StayFD _n_RQ_CreateDt;

extern StayDate J_DateProt;
extern StayFD *_J_DateProt;
extern StayFD _n_J_DateProt;

extern char J_StrDoc[51];
extern StayFD *_J_StrDoc;
extern StayFD _n_J_StrDoc;

extern char J_OSZNAME[51];
extern StayFD *_J_OSZNAME;
extern StayFD _n_J_OSZNAME;

extern char J_StrAns[51];
extern StayFD *_J_StrAns;
extern StayFD _n_J_StrAns;

/* End FHfield */
/* Begin FHdataset */
extern StayDataset _n_B_JsonDnd;
extern StayDataset *B_JsonDnd;
/* End FHdataset */
/* Begin FHmenu */
/* End FHmenu */
/* Begin FHframe */
/* End FHframe */
/* Begin FHtabl */
extern void *JSONDND[];
/* End FHtabl */
/* Begin FDfield */
/* End FDfield */
/* Begin FDextern */
/* End FDextern */
/* Begin FHend */

HPICMODULEEND(JSONDND)

#endif
/* End FHend */
