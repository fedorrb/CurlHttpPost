/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file JSONDND.XME
//-------------------------------------------------------------------------
// Created 22\08\2018 16:39
//-------------------------------------------------------------------------

#include "JSONDND.h"

/* End FCbegin */
/* Begin FCinclude */
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(JSONDND)

static StayFD _nn_JSONDND = {NULL,TAG_PIC,0,0,0,0,"JSONDND",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
BYTE  RQ_Ver;
StayFD _n_RQ_Ver = {&RQ_Ver,0,0,0,CLS_S,0,"RQ_Ver","Версия формата обмена"};
StayFD *_RQ_Ver = &_n_RQ_Ver;

WORD  RQ_State;
StayFD _n_RQ_State = {&RQ_State,0,0,0,CLS_I,0,"RQ_State","Код состояния"};
StayFD *_RQ_State = &_n_RQ_State;

DWORD RQ_Ident;
StayFD _n_RQ_Ident = {&RQ_Ident,0,0,0,CLS_L,0,"RQ_Ident","Идентификатор записи"};
StayFD *_RQ_Ident = &_n_RQ_Ident;

DWORD RQ_Nls;
StayFD _n_RQ_Nls = {&RQ_Nls,0,0,0,CLS_L,0,"RQ_Nls","Номер лицевого"};
StayFD *_RQ_Nls = &_n_RQ_Nls;

WORD  RQ_Raj;
StayFD _n_RQ_Raj = {&RQ_Raj,0,0,0,CLS_I,0,"RQ_Raj","Номер района"};
StayFD *_RQ_Raj = &_n_RQ_Raj;

char RQ_PrntSName[26];
StayFD _n_RQ_PrntSName = {&RQ_PrntSName,0,0,0,CLS_V,25,"RQ_PrntSName","Фамилия заявителя"};
StayFD *_RQ_PrntSName = &_n_RQ_PrntSName;

char RQ_PrntMName[26];
StayFD _n_RQ_PrntMName = {&RQ_PrntMName,0,0,0,CLS_V,25,"RQ_PrntMName","Имя заявителя"};
StayFD *_RQ_PrntMName = &_n_RQ_PrntMName;

char RQ_PrntLName[26];
StayFD _n_RQ_PrntLName = {&RQ_PrntLName,0,0,0,CLS_V,25,"RQ_PrntLName","Отчество заявителя"};
StayFD *_RQ_PrntLName = &_n_RQ_PrntLName;

char RQ_PId[11];
StayFD _n_RQ_PId = {&RQ_PId,0,0,0,CLS_V,10,"RQ_PId","Налоговый номер заявителя"};
StayFD *_RQ_PId = &_n_RQ_PId;

BYTE  RQ_PasspType;
StayFD _n_RQ_PasspType = {&RQ_PasspType,0,0,0,CLS_S,0,"RQ_PasspType","Тип паспорта заявителя 1 старый, 2 новый"};
StayFD *_RQ_PasspType = &_n_RQ_PasspType;

char RQ_PaspSN[16];
StayFD _n_RQ_PaspSN = {&RQ_PaspSN,0,0,0,CLS_V,15,"RQ_PaspSN","Серия Номер паспорта"};
StayFD *_RQ_PaspSN = &_n_RQ_PaspSN;

StayDate RQ_PaspDt;
StayFD _n_RQ_PaspDt = {&RQ_PaspDt,0,0,0,CLS_Date,0,"RQ_PaspDt","Дата выдачи паспорта"};
StayFD *_RQ_PaspDt = &_n_RQ_PaspDt;

StayDate RQ_BirthDtP;
StayFD _n_RQ_BirthDtP = {&RQ_BirthDtP,0,0,0,CLS_Date,0,"RQ_BirthDtP","Дата рождения заявителя"};
StayFD *_RQ_BirthDtP = &_n_RQ_BirthDtP;

char RQ_ChldSName[26];
StayFD _n_RQ_ChldSName = {&RQ_ChldSName,0,0,0,CLS_V,25,"RQ_ChldSName","Фамилия ребенка"};
StayFD *_RQ_ChldSName = &_n_RQ_ChldSName;

char RQ_ChldMName[26];
StayFD _n_RQ_ChldMName = {&RQ_ChldMName,0,0,0,CLS_V,25,"RQ_ChldMName","Имя ребенка"};
StayFD *_RQ_ChldMName = &_n_RQ_ChldMName;

char RQ_ChldLName[26];
StayFD _n_RQ_ChldLName = {&RQ_ChldLName,0,0,0,CLS_V,25,"RQ_ChldLName","Отчество ребенка"};
StayFD *_RQ_ChldLName = &_n_RQ_ChldLName;

StayDate RQ_BirthDtC;
StayFD _n_RQ_BirthDtC = {&RQ_BirthDtC,0,0,0,CLS_Date,0,"RQ_BirthDtC","Дата рождения ребенка"};
StayFD *_RQ_BirthDtC = &_n_RQ_BirthDtC;

char RQ_SvidSN[26];
StayFD _n_RQ_SvidSN = {&RQ_SvidSN,0,0,0,CLS_V,25,"RQ_SvidSN","Серия номер свидетельства о рождении ребенка"};
StayFD *_RQ_SvidSN = &_n_RQ_SvidSN;

StayDate RQ_SvidDt;
StayFD _n_RQ_SvidDt = {&RQ_SvidDt,0,0,0,CLS_Date,0,"RQ_SvidDt","Дата выдачи свидет о рожден"};
StayFD *_RQ_SvidDt = &_n_RQ_SvidDt;

WORD  RQ_Insp;
StayFD _n_RQ_Insp = {&RQ_Insp,0,0,0,CLS_I,0,"RQ_Insp","Код инспектора"};
StayFD *_RQ_Insp = &_n_RQ_Insp;

char RQ_InspFio[51];
StayFD _n_RQ_InspFio = {&RQ_InspFio,0,0,0,CLS_V,50,"RQ_InspFio",""};
StayFD *_RQ_InspFio = &_n_RQ_InspFio;

StayDate RQ_CreateDt;
StayFD _n_RQ_CreateDt = {&RQ_CreateDt,0,0,0,CLS_Date,0,"RQ_CreateDt","Дата формирования запроса"};
StayFD *_RQ_CreateDt = &_n_RQ_CreateDt;

StayDate J_DateProt;
StayFD _n_J_DateProt = {&J_DateProt,0,0,0,CLS_Date,0,"J_DateProt",""};
StayFD *_J_DateProt = &_n_J_DateProt;

char J_StrDoc[51];
StayFD _n_J_StrDoc = {&J_StrDoc,0,0,0,CLS_V,50,"J_StrDoc",""};
StayFD *_J_StrDoc = &_n_J_StrDoc;

char J_OSZNAME[51];
StayFD _n_J_OSZNAME = {&J_OSZNAME,0,0,0,CLS_V,50,"J_OSZNAME",""};
StayFD *_J_OSZNAME = &_n_J_OSZNAME;

char J_StrAns[51];
StayFD _n_J_StrAns = {&J_StrAns,0,0,0,CLS_V,50,"J_StrAns",""};
StayFD *_J_StrAns = &_n_J_StrAns;

/* End FCfield */
/* Begin FCextern */
extern StayDataset _n_B_JsonDnd;
/* End FCextern */
/* Begin FCdataset */
static StayFD *tcm_B_JsonDnd[] =
{
 (StayFD *)&_n_RQ_Ver,
 (StayFD *)&_n_RQ_State,
 (StayFD *)&_n_RQ_Ident,
 (StayFD *)&_n_RQ_Nls,
 (StayFD *)&_n_RQ_Raj,
 (StayFD *)&_n_RQ_PrntSName,
 (StayFD *)&_n_RQ_PrntMName,
 (StayFD *)&_n_RQ_PrntLName,
 (StayFD *)&_n_RQ_PId,
 (StayFD *)&_n_RQ_PasspType,
 (StayFD *)&_n_RQ_PaspSN,
 (StayFD *)&_n_RQ_PaspDt,
 (StayFD *)&_n_RQ_BirthDtP,
 (StayFD *)&_n_RQ_ChldSName,
 (StayFD *)&_n_RQ_ChldMName,
 (StayFD *)&_n_RQ_ChldLName,
 (StayFD *)&_n_RQ_BirthDtC,
 (StayFD *)&_n_RQ_SvidSN,
 (StayFD *)&_n_RQ_SvidDt,
 (StayFD *)&_n_RQ_Insp,
 (StayFD *)&_n_RQ_InspFio,
 (StayFD *)&_n_RQ_CreateDt,
 NULL
};
StayDataset _n_B_JsonDnd = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_JsonDnd,NULL,
"WORK:JSONDND.DT",NULL,NULL,"B_JsonDnd",0};
StayDataset *B_JsonDnd = &_n_B_JsonDnd;

/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */
/* End FCframe */
/* Begin FCtabl */
void *JSONDND[] =
 {NULL,
  &_nn_JSONDND,
  &_n_RQ_Ver,
  &_n_RQ_State,
  &_n_RQ_Ident,
  &_n_RQ_Nls,
  &_n_RQ_Raj,
  &_n_RQ_PrntSName,
  &_n_RQ_PrntMName,
  &_n_RQ_PrntLName,
  &_n_RQ_PId,
  &_n_RQ_PasspType,
  &_n_RQ_PaspSN,
  &_n_RQ_PaspDt,
  &_n_RQ_BirthDtP,
  &_n_RQ_ChldSName,
  &_n_RQ_ChldMName,
  &_n_RQ_ChldLName,
  &_n_RQ_BirthDtC,
  &_n_RQ_SvidSN,
  &_n_RQ_SvidDt,
  &_n_RQ_Insp,
  &_n_RQ_InspFio,
  &_n_RQ_CreateDt,
  &_n_J_DateProt,
  &_n_J_StrDoc,
  &_n_J_OSZNAME,
  &_n_J_StrAns,
  (StayFD *)B_JsonDnd,
  NULL};

PICMODULEEND(JSONDND)

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
