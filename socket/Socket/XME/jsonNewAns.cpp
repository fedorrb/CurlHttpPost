/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file JSONNEWANS.XME
//-------------------------------------------------------------------------
// Created 12\06\2019 15:56
//-------------------------------------------------------------------------

#include "JSONNEWANS.h"

/* End FCbegin */
/* Begin FCinclude */
#include "jsondndans.h"
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(JSONNEWANS)

static StayFD _nn_JSONNEWANS = {NULL,TAG_PIC,0,0,0,0,"JSONNEWANS",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
StayDate RS_DBeg;
StayFD _n_RS_DBeg = {&RS_DBeg,0,0,0,CLS_Date,0,"RS_DBeg","дата \" З \""};
StayFD *_RS_DBeg = &_n_RS_DBeg;

StayDate RS_DEnd;
StayFD _n_RS_DEnd = {&RS_DEnd,0,0,0,CLS_Date,0,"RS_DEnd","дата ПО"};
StayFD *_RS_DEnd = &_n_RS_DEnd;

StayDate RS_DOpiki;
StayFD _n_RS_DOpiki = {&RS_DOpiki,0,0,0,CLS_Date,0,"RS_DOpiki","дата встановлення опікі"};
StayFD *_RS_DOpiki = &_n_RS_DOpiki;

StayDate RS_DZnat;
StayFD _n_RS_DZnat = {&RS_DZnat,0,0,0,CLS_Date,0,"RS_DZnat","дата зняття з обліку члена семьи"};
StayFD *_RS_DZnat = &_n_RS_DZnat;

char RS_FamIgd[26];
StayFD _n_RS_FamIgd = {&RS_FamIgd,0,0,0,CLS_V,25,"RS_FamIgd","фамилия члена семьи"};
StayFD *_RS_FamIgd = &_n_RS_FamIgd;

DWORD RS_Ident;
StayFD _n_RS_Ident = {&RS_Ident,0,0,0,CLS_L,0,"RS_Ident","Идентификатор записи"};
StayFD *_RS_Ident = &_n_RS_Ident;

char RS_IdIgd[11];
StayFD _n_RS_IdIgd = {&RS_IdIgd,0,0,0,CLS_V,10,"RS_IdIgd","ИД код члена семьи"};
StayFD *_RS_IdIgd = &_n_RS_IdIgd;

StayDate RS_DataAktZap;
StayFD _n_RS_DataAktZap = {&RS_DataAktZap,0,0,0,CLS_Date,0,"RS_DataAktZap","Член Семьи дата Актового запису"};
StayFD *_RS_DataAktZap = &_n_RS_DataAktZap;

StayDate RS_IgdDtR;
StayFD _n_RS_IgdDtR = {&RS_IgdDtR,0,0,0,CLS_Date,0,"RS_IgdDtR","Дата рождения члена семьи"};
StayFD *_RS_IgdDtR = &_n_RS_IgdDtR;

char RS_NomAktZap[12];
StayFD _n_RS_NomAktZap = {&RS_NomAktZap,0,0,0,CLS_V,11,"RS_NomAktZap","Член Семьи номер Актового запису"};
StayFD *_RS_NomAktZap = &_n_RS_NomAktZap;

char RS_IgdPaspSN[26];
StayFD _n_RS_IgdPaspSN = {&RS_IgdPaspSN,0,0,0,CLS_V,25,"RS_IgdPaspSN","Член Семьи Серия Номер паспорта"};
StayFD *_RS_IgdPaspSN = &_n_RS_IgdPaspSN;

BYTE  RS_IgdPspType;
StayFD _n_RS_IgdPspType = {&RS_IgdPspType,0,0,0,CLS_S,0,"RS_IgdPspType","Член Семьи Тип паспорта заявитея 1 старый, 2 новый 3 свід.про народж 4 інший докум"};
StayFD *_RS_IgdPspType = &_n_RS_IgdPspType;

char RS_IgdUNZR[14];
StayFD _n_RS_IgdUNZR = {&RS_IgdUNZR,0,0,0,CLS_V,13,"RS_IgdUNZR","Член Семьи номер УНЗР"};
StayFD *_RS_IgdUNZR = &_n_RS_IgdUNZR;

char RS_IgdVidan[5];
StayFD _n_RS_IgdVidan = {&RS_IgdVidan,0,0,0,CLS_V,4,"RS_IgdVidan","Член Семьи кем выдан паспорт тип 2 образца 2016 года"};
StayFD *_RS_IgdVidan = &_n_RS_IgdVidan;

char RS_ImaIgd[26];
StayFD _n_RS_ImaIgd = {&RS_ImaIgd,0,0,0,CLS_V,25,"RS_ImaIgd","имя члена семьи"};
StayFD *_RS_ImaIgd = &_n_RS_ImaIgd;

BYTE  RS_KatZ;
StayFD _n_RS_KatZ = {&RS_KatZ,0,0,0,CLS_S,0,"RS_KatZ","категория заявника 1 - заявник"};
StayFD *_RS_KatZ = &_n_RS_KatZ;

WORD  RS_Kfn;
StayFD _n_RS_Kfn = {&RS_Kfn,0,0,0,CLS_I,0,"RS_Kfn","код выплаты"};
StayFD *_RS_Kfn = &_n_RS_Kfn;

BYTE  RS_NomIgd;
StayFD _n_RS_NomIgd = {&RS_NomIgd,0,0,0,CLS_S,0,"RS_NomIgd","порядковій номер члена семьи"};
StayFD *_RS_NomIgd = &_n_RS_NomIgd;

char RS_OtIgd[26];
StayFD _n_RS_OtIgd = {&RS_OtIgd,0,0,0,CLS_V,25,"RS_OtIgd","отчество члена семьи"};
StayFD *_RS_OtIgd = &_n_RS_OtIgd;

BYTE  RS_Oznaka;
StayFD _n_RS_Oznaka = {&RS_Oznaka,0,0,0,CLS_S,0,"RS_Oznaka","социальна ознака 1 - допомога"};
StayFD *_RS_Oznaka = &_n_RS_Oznaka;

BYTE  RS_Psn;
StayFD _n_RS_Psn = {&RS_Psn,0,0,0,CLS_S,0,"RS_Psn","причина зняття з обліку члена семьи"};
StayFD *_RS_Psn = &_n_RS_Psn;

char RS_UNZR[14];
StayFD _n_RS_UNZR = {&RS_UNZR,0,0,0,CLS_V,13,"RS_UNZR","номер УНЗР"};
StayFD *_RS_UNZR = &_n_RS_UNZR;

char RS_Vidan[5];
StayFD _n_RS_Vidan = {&RS_Vidan,0,0,0,CLS_V,4,"RS_Vidan","кем выдан паспорт тип 2 образца 2016 года"};
StayFD *_RS_Vidan = &_n_RS_Vidan;

/* End FCfield */
/* Begin FCextern */
extern StayDataset _n_B_DetiAns;
extern StayDataset _n_B_PologiAns;
extern StayDataset _n_B_StopAns;
/* End FCextern */
/* Begin FCdataset */
static StayFD *tcm_B_DetiAns[] =
{
 (StayFD *)&_n_RS_Answer,
 (StayFD *)&_n_RS_Message,
 (StayFD *)&_n_RS_State,
 (StayFD *)&_n_RS_Ident,
 (StayFD *)&_n_RS_Insp,
 (StayFD *)&_n_RS_InspFio,
 (StayFD *)&_n_RS_CreateDt,
 (StayFD *)&_n_RS_Nls,
 (StayFD *)&_n_RS_Raj,
 (StayFD *)&_n_RS_Oznaka,
 (StayFD *)&_n_RS_Kfn,
 (StayFD *)&_n_RS_DBeg,
 (StayFD *)&_n_RS_DEnd,
 (StayFD *)&_n_RS_KatZ,
 (StayFD *)&_n_RS_PrntSName,
 (StayFD *)&_n_RS_PrntMName,
 (StayFD *)&_n_RS_PrntLName,
 (StayFD *)&_n_RS_PId,
 (StayFD *)&_n_RS_PasspType,
 (StayFD *)&_n_RS_PaspSN,
 (StayFD *)&_n_RS_PaspDt,
 (StayFD *)&_n_RS_BirthDtP,
 (StayFD *)&_n_RS_NomIgd,
 (StayFD *)&_n_RS_FamIgd,
 (StayFD *)&_n_RS_ImaIgd,
 (StayFD *)&_n_RS_OtIgd,
 (StayFD *)&_n_RS_IgdDtR,
 (StayFD *)&_n_RS_IdIgd,
 (StayFD *)&_n_RS_IgdPspType,
 (StayFD *)&_n_RS_IgdPaspSN,
 (StayFD *)&_n_RS_NomAktZap,
 (StayFD *)&_n_RS_DataAktZap,
 (StayFD *)&_n_RS_DOpiki,
 (StayFD *)&_n_RS_DZnat,
 (StayFD *)&_n_RS_Psn,
 NULL
};
StayDataset _n_B_DetiAns = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_DetiAns,NULL,
"WORK:JSONDETIANS.DT",NULL,"база ответа Допомога детям разные виды  NATA","B_DetiAns",0};
StayDataset *B_DetiAns = &_n_B_DetiAns;

static StayFD *tcm_B_PologiAns[] =
{
 (StayFD *)&_n_RS_Answer,
 (StayFD *)&_n_RS_Message,
 (StayFD *)&_n_RS_State,
 (StayFD *)&_n_RS_Ident,
 (StayFD *)&_n_RS_Insp,
 (StayFD *)&_n_RS_InspFio,
 (StayFD *)&_n_RS_CreateDt,
 (StayFD *)&_n_RS_Nls,
 (StayFD *)&_n_RS_Raj,
 (StayFD *)&_n_RS_Oznaka,
 (StayFD *)&_n_RS_Kfn,
 (StayFD *)&_n_RS_DBeg,
 (StayFD *)&_n_RS_DEnd,
 (StayFD *)&_n_RS_KatZ,
 (StayFD *)&_n_RS_PrntSName,
 (StayFD *)&_n_RS_PrntMName,
 (StayFD *)&_n_RS_PrntLName,
 (StayFD *)&_n_RS_PId,
 (StayFD *)&_n_RS_PasspType,
 (StayFD *)&_n_RS_PaspSN,
 (StayFD *)&_n_RS_PaspDt,
 (StayFD *)&_n_RS_BirthDtP,
 NULL
};
StayDataset _n_B_PologiAns = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_PologiAns,NULL,
"WORK:JSONPOLOGIANS.DT",NULL,"база ответа Допомога по вагітності та пологам  NATA","B_PologiAns",0};
StayDataset *B_PologiAns = &_n_B_PologiAns;

static StayFD *tcm_B_StopAns[] =
{
 (StayFD *)&_n_RS_Answer,
 (StayFD *)&_n_RS_Message,
 NULL
};
StayDataset _n_B_StopAns = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_StopAns,NULL,
"WORK:STOPANS.DT",NULL,NULL,"B_StopAns",0};
StayDataset *B_StopAns = &_n_B_StopAns;

/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */
/* End FCframe */
/* Begin FCtabl */
void *JSONNEWANS[] =
 {NULL,
  &_nn_JSONNEWANS,
  &_n_RS_DBeg,
  &_n_RS_DEnd,
  &_n_RS_DOpiki,
  &_n_RS_DZnat,
  &_n_RS_FamIgd,
  &_n_RS_Ident,
  &_n_RS_IdIgd,
  &_n_RS_DataAktZap,
  &_n_RS_IgdDtR,
  &_n_RS_NomAktZap,
  &_n_RS_IgdPaspSN,
  &_n_RS_IgdPspType,
  &_n_RS_IgdUNZR,
  &_n_RS_IgdVidan,
  &_n_RS_ImaIgd,
  &_n_RS_KatZ,
  &_n_RS_Kfn,
  &_n_RS_NomIgd,
  &_n_RS_OtIgd,
  &_n_RS_Oznaka,
  &_n_RS_Psn,
  &_n_RS_UNZR,
  &_n_RS_Vidan,
  (StayFD *)B_DetiAns,
  (StayFD *)B_PologiAns,
  (StayFD *)B_StopAns,
  NULL};

PICMODULEEND(JSONNEWANS)

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
