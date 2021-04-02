/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file JSONNEWREQ.XME
//-------------------------------------------------------------------------
// Created 12\06\2019 15:54
//-------------------------------------------------------------------------

#include "JSONNEWREQ.h"

/* End FCbegin */
/* Begin FCinclude */
#include "jsondnd.h"
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(JSONNEWREQ)

static StayFD _nn_JSONNEWREQ = {NULL,TAG_PIC,0,0,0,0,"JSONNEWREQ",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
StayDate RQ_DBeg;
StayFD _n_RQ_DBeg = {&RQ_DBeg,0,0,0,CLS_Date,0,"RQ_DBeg","дата \" З \""};
StayFD *_RQ_DBeg = &_n_RQ_DBeg;

StayDate RQ_DEnd;
StayFD _n_RQ_DEnd = {&RQ_DEnd,0,0,0,CLS_Date,0,"RQ_DEnd","дата ПО"};
StayFD *_RQ_DEnd = &_n_RQ_DEnd;

StayDate RQ_DOpiki;
StayFD _n_RQ_DOpiki = {&RQ_DOpiki,0,0,0,CLS_Date,0,"RQ_DOpiki","дата встановлення опікі"};
StayFD *_RQ_DOpiki = &_n_RQ_DOpiki;

StayDate RQ_DZnat;
StayFD _n_RQ_DZnat = {&RQ_DZnat,0,0,0,CLS_Date,0,"RQ_DZnat","дата зняття з обліку члена семьи"};
StayFD *_RQ_DZnat = &_n_RQ_DZnat;

char RQ_FamIgd[26];
StayFD _n_RQ_FamIgd = {&RQ_FamIgd,0,0,0,CLS_V,25,"RQ_FamIgd","фамилия члена семьи"};
StayFD *_RQ_FamIgd = &_n_RQ_FamIgd;

char RQ_IdIgd[11];
StayFD _n_RQ_IdIgd = {&RQ_IdIgd,0,0,0,CLS_V,10,"RQ_IdIgd","ИД код члена семьи"};
StayFD *_RQ_IdIgd = &_n_RQ_IdIgd;

StayDate RQ_DataAktZap;
StayFD _n_RQ_DataAktZap = {&RQ_DataAktZap,0,0,0,CLS_Date,0,"RQ_DataAktZap","Член Семьи дата Актового запису"};
StayFD *_RQ_DataAktZap = &_n_RQ_DataAktZap;

StayDate RQ_IgdDtR;
StayFD _n_RQ_IgdDtR = {&RQ_IgdDtR,0,0,0,CLS_Date,0,"RQ_IgdDtR","Дата рождения члена семьи"};
StayFD *_RQ_IgdDtR = &_n_RQ_IgdDtR;

char RQ_NomAktZap[12];
StayFD _n_RQ_NomAktZap = {&RQ_NomAktZap,0,0,0,CLS_V,11,"RQ_NomAktZap","Член Семьи номер Актового запису"};
StayFD *_RQ_NomAktZap = &_n_RQ_NomAktZap;

char RQ_IgdPaspSN[26];
StayFD _n_RQ_IgdPaspSN = {&RQ_IgdPaspSN,0,0,0,CLS_V,25,"RQ_IgdPaspSN","Член Семьи Серия Номер паспорта"};
StayFD *_RQ_IgdPaspSN = &_n_RQ_IgdPaspSN;

BYTE  RQ_IgdPspType;
StayFD _n_RQ_IgdPspType = {&RQ_IgdPspType,0,0,0,CLS_S,0,"RQ_IgdPspType","Член Семьи Тип паспорта заявитея 1 старый, 2 новый 3 свід.про народж 4 інший докум"};
StayFD *_RQ_IgdPspType = &_n_RQ_IgdPspType;

char RQ_IgdUNZR[14];
StayFD _n_RQ_IgdUNZR = {&RQ_IgdUNZR,0,0,0,CLS_V,13,"RQ_IgdUNZR","Член Семьи номер УНЗР"};
StayFD *_RQ_IgdUNZR = &_n_RQ_IgdUNZR;

char RQ_IgdVidan[5];
StayFD _n_RQ_IgdVidan = {&RQ_IgdVidan,0,0,0,CLS_V,4,"RQ_IgdVidan","Член Семьи кем выдан паспорт тип 2 образца 2016 года"};
StayFD *_RQ_IgdVidan = &_n_RQ_IgdVidan;

char RQ_ImaIgd[26];
StayFD _n_RQ_ImaIgd = {&RQ_ImaIgd,0,0,0,CLS_V,25,"RQ_ImaIgd","имя члена семьи"};
StayFD *_RQ_ImaIgd = &_n_RQ_ImaIgd;

BYTE  RQ_KatZ;
StayFD _n_RQ_KatZ = {&RQ_KatZ,0,0,0,CLS_S,0,"RQ_KatZ","категория заявника 1 - заявник"};
StayFD *_RQ_KatZ = &_n_RQ_KatZ;

WORD  RQ_Kfn;
StayFD _n_RQ_Kfn = {&RQ_Kfn,0,0,0,CLS_I,0,"RQ_Kfn","код выплаты"};
StayFD *_RQ_Kfn = &_n_RQ_Kfn;

BYTE  RQ_NomIgd;
StayFD _n_RQ_NomIgd = {&RQ_NomIgd,0,0,0,CLS_S,0,"RQ_NomIgd","порядковій номер члена семьи"};
StayFD *_RQ_NomIgd = &_n_RQ_NomIgd;

char RQ_OtIgd[26];
StayFD _n_RQ_OtIgd = {&RQ_OtIgd,0,0,0,CLS_V,25,"RQ_OtIgd","отчество члена семьи"};
StayFD *_RQ_OtIgd = &_n_RQ_OtIgd;

BYTE  RQ_Oznaka;
StayFD _n_RQ_Oznaka = {&RQ_Oznaka,0,0,0,CLS_S,0,"RQ_Oznaka","социальна ознака 1 - допомога"};
StayFD *_RQ_Oznaka = &_n_RQ_Oznaka;

BYTE  RQ_Psn;
StayFD _n_RQ_Psn = {&RQ_Psn,0,0,0,CLS_S,0,"RQ_Psn","причина зняття з обліку члена семьи"};
StayFD *_RQ_Psn = &_n_RQ_Psn;

char RQ_UNZR[14];
StayFD _n_RQ_UNZR = {&RQ_UNZR,0,0,0,CLS_V,13,"RQ_UNZR","номер УНЗР"};
StayFD *_RQ_UNZR = &_n_RQ_UNZR;

char RQ_Vidan[5];
StayFD _n_RQ_Vidan = {&RQ_Vidan,0,0,0,CLS_V,4,"RQ_Vidan","кем выдан паспорт тип 2 образца 2016 года"};
StayFD *_RQ_Vidan = &_n_RQ_Vidan;

/* End FCfield */
/* Begin FCextern */
extern StayDataset _n_B_DetiReq;
extern StayDataset _n_B_PologiReq;
extern StayDataset _n_B_Stop;
/* End FCextern */
/* Begin FCdataset */
static StayFD *tcm_B_DetiReq[] =
{
 (StayFD *)&_n_RQ_Ident,
 (StayFD *)&_n_RQ_State,
 (StayFD *)&_n_RQ_Insp,
 (StayFD *)&_n_RQ_InspFio,
 (StayFD *)&_n_RQ_CreateDt,
 (StayFD *)&_n_RQ_Nls,
 (StayFD *)&_n_RQ_Raj,
 (StayFD *)&_n_RQ_Oznaka,
 (StayFD *)&_n_RQ_Kfn,
 (StayFD *)&_n_RQ_DBeg,
 (StayFD *)&_n_RQ_DEnd,
 (StayFD *)&_n_RQ_KatZ,
 (StayFD *)&_n_RQ_PrntSName,
 (StayFD *)&_n_RQ_PrntMName,
 (StayFD *)&_n_RQ_PrntLName,
 (StayFD *)&_n_RQ_PId,
 (StayFD *)&_n_RQ_PasspType,
 (StayFD *)&_n_RQ_PaspSN,
 (StayFD *)&_n_RQ_PaspDt,
 (StayFD *)&_n_RQ_BirthDtP,
 (StayFD *)&_n_RQ_NomIgd,
 (StayFD *)&_n_RQ_FamIgd,
 (StayFD *)&_n_RQ_ImaIgd,
 (StayFD *)&_n_RQ_OtIgd,
 (StayFD *)&_n_RQ_IgdDtR,
 (StayFD *)&_n_RQ_IdIgd,
 (StayFD *)&_n_RQ_IgdPspType,
 (StayFD *)&_n_RQ_IgdPaspSN,
 (StayFD *)&_n_RQ_NomAktZap,
 (StayFD *)&_n_RQ_DataAktZap,
 (StayFD *)&_n_RQ_DOpiki,
 (StayFD *)&_n_RQ_DZnat,
 (StayFD *)&_n_RQ_Psn,
 NULL
};
StayDataset _n_B_DetiReq = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_DetiReq,NULL,
"WORK:JSONDETI.DT",NULL,"база запроса Допомога детям разные виды  NATA","B_DetiReq",0};
StayDataset *B_DetiReq = &_n_B_DetiReq;

static StayFD *tcm_B_PologiReq[] =
{
 (StayFD *)&_n_RQ_Ident,
 (StayFD *)&_n_RQ_State,
 (StayFD *)&_n_RQ_Insp,
 (StayFD *)&_n_RQ_InspFio,
 (StayFD *)&_n_RQ_CreateDt,
 (StayFD *)&_n_RQ_Nls,
 (StayFD *)&_n_RQ_Raj,
 (StayFD *)&_n_RQ_Oznaka,
 (StayFD *)&_n_RQ_Kfn,
 (StayFD *)&_n_RQ_DBeg,
 (StayFD *)&_n_RQ_DEnd,
 (StayFD *)&_n_RQ_KatZ,
 (StayFD *)&_n_RQ_PrntSName,
 (StayFD *)&_n_RQ_PrntMName,
 (StayFD *)&_n_RQ_PrntLName,
 (StayFD *)&_n_RQ_PId,
 (StayFD *)&_n_RQ_PasspType,
 (StayFD *)&_n_RQ_PaspSN,
 (StayFD *)&_n_RQ_PaspDt,
 (StayFD *)&_n_RQ_BirthDtP,
 NULL
};
StayDataset _n_B_PologiReq = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_PologiReq,NULL,
"WORK:JSONPOLOGI.DT",NULL,"база запроса Допомога по вагітності та пологам  NATA","B_PologiReq",0};
StayDataset *B_PologiReq = &_n_B_PologiReq;

static StayFD *tcm_B_Stop[] =
{
 (StayFD *)&_n_RQ_Ident,
 (StayFD *)&_n_RQ_State,
 (StayFD *)&_n_RQ_Insp,
 (StayFD *)&_n_RQ_InspFio,
 (StayFD *)&_n_RQ_CreateDt,
 (StayFD *)&_n_RQ_Nls,
 (StayFD *)&_n_RQ_Raj,
 (StayFD *)&_n_RQ_Oznaka,
 (StayFD *)&_n_RQ_Kfn,
 (StayFD *)&_n_RQ_DBeg,
 (StayFD *)&_n_RQ_DEnd,
 (StayFD *)&_n_RQ_Psn,
 NULL
};
StayDataset _n_B_Stop = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_Stop,NULL,
"WORK:STOP.DT",NULL,"база запроса по припиненим і переїхавщим","B_Stop",0};
StayDataset *B_Stop = &_n_B_Stop;

/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */
/* End FCframe */
/* Begin FCtabl */
void *JSONNEWREQ[] =
 {NULL,
  &_nn_JSONNEWREQ,
  &_n_RQ_DBeg,
  &_n_RQ_DEnd,
  &_n_RQ_DOpiki,
  &_n_RQ_DZnat,
  &_n_RQ_FamIgd,
  &_n_RQ_IdIgd,
  &_n_RQ_DataAktZap,
  &_n_RQ_IgdDtR,
  &_n_RQ_NomAktZap,
  &_n_RQ_IgdPaspSN,
  &_n_RQ_IgdPspType,
  &_n_RQ_IgdUNZR,
  &_n_RQ_IgdVidan,
  &_n_RQ_ImaIgd,
  &_n_RQ_KatZ,
  &_n_RQ_Kfn,
  &_n_RQ_NomIgd,
  &_n_RQ_OtIgd,
  &_n_RQ_Oznaka,
  &_n_RQ_Psn,
  &_n_RQ_UNZR,
  &_n_RQ_Vidan,
  (StayFD *)B_DetiReq,
  (StayFD *)B_PologiReq,
  (StayFD *)B_Stop,
  NULL};

PICMODULEEND(JSONNEWREQ)

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
