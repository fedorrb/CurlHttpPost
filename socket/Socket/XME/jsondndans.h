/* Begin FHbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource header file JSONDNDANS.XME
//-------------------------------------------------------------------------
// Created 21\08\2018 14:10
//-------------------------------------------------------------------------

/* End FHbegin */
/* Begin FHhead */
#ifndef _JSONDNDANS_H_
#define _JSONDNDANS_H_

#include "staypic.h"
HPICMODULEBEG(JSONDNDANS)

/* End FHhead */
/* Begin FHdefine */
/* End FHdefine */
/* Begin FHtypedef */
/* End FHtypedef */
/* Begin FHfield */
extern BYTE  RS_Ver;
extern StayFD *_RS_Ver;
extern StayFD _n_RS_Ver;

extern WORD  RS_State;
extern StayFD *_RS_State;
extern StayFD _n_RS_State;

extern short RS_Answer;
extern StayFD *_RS_Answer;
extern StayFD _n_RS_Answer;

extern char RS_Message[251];
extern StayFD *_RS_Message;
extern StayFD _n_RS_Message;

extern WORD  RS_Raj;
extern StayFD *_RS_Raj;
extern StayFD _n_RS_Raj;

extern DWORD RS_Nls;
extern StayFD *_RS_Nls;
extern StayFD _n_RS_Nls;

extern char RS_PrntSName[26];
extern StayFD *_RS_PrntSName;
extern StayFD _n_RS_PrntSName;

extern char RS_PrntMName[26];
extern StayFD *_RS_PrntMName;
extern StayFD _n_RS_PrntMName;

extern char RS_PrntLName[26];
extern StayFD *_RS_PrntLName;
extern StayFD _n_RS_PrntLName;

extern char RS_PId[11];
extern StayFD *_RS_PId;
extern StayFD _n_RS_PId;

extern BYTE  RS_PasspType;
extern StayFD *_RS_PasspType;
extern StayFD _n_RS_PasspType;

extern char RS_PaspSN[26];
extern StayFD *_RS_PaspSN;
extern StayFD _n_RS_PaspSN;

extern StayDate RS_PaspDt;
extern StayFD *_RS_PaspDt;
extern StayFD _n_RS_PaspDt;

extern StayDate RS_BirthDtP;
extern StayFD *_RS_BirthDtP;
extern StayFD _n_RS_BirthDtP;

extern char RS_ChldSName[26];
extern StayFD *_RS_ChldSName;
extern StayFD _n_RS_ChldSName;

extern char RS_ChldMName[26];
extern StayFD *_RS_ChldMName;
extern StayFD _n_RS_ChldMName;

extern char RS_ChldLName[26];
extern StayFD *_RS_ChldLName;
extern StayFD _n_RS_ChldLName;

extern StayDate RS_BirthDtC;
extern StayFD *_RS_BirthDtC;
extern StayFD _n_RS_BirthDtC;

extern char RS_SvidSN[26];
extern StayFD *_RS_SvidSN;
extern StayFD _n_RS_SvidSN;

extern StayDate RS_SvidDt;
extern StayFD *_RS_SvidDt;
extern StayFD _n_RS_SvidDt;

extern WORD  RS_Insp;
extern StayFD *_RS_Insp;
extern StayFD _n_RS_Insp;

extern char RS_InspFio[51];
extern StayFD *_RS_InspFio;
extern StayFD _n_RS_InspFio;

extern StayDate RS_CreateDt;
extern StayFD *_RS_CreateDt;
extern StayFD _n_RS_CreateDt;

/* End FHfield */
/* Begin FHdataset */
extern StayDataset _n_B_JsonDndAns;
extern StayDataset *B_JsonDndAns;
/* End FHdataset */
/* Begin FHmenu */
/* End FHmenu */
/* Begin FHframe */
/* End FHframe */
/* Begin FHtabl */
extern void *JSONDNDANS[];
/* End FHtabl */
/* Begin FDfield */
/* End FDfield */
/* Begin FDextern */
/* End FDextern */
/* Begin FHend */

HPICMODULEEND(JSONDNDANS)

#endif
/* End FHend */
