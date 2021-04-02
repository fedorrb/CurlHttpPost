/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file JSONDNDANS.XME
//-------------------------------------------------------------------------
// Created 21\08\2018 14:10
//-------------------------------------------------------------------------

#include "JSONDNDANS.h"

/* End FCbegin */
/* Begin FCinclude */
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(JSONDNDANS)

static StayFD _nn_JSONDNDANS = {NULL,TAG_PIC,0,0,0,0,"JSONDNDANS",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
BYTE  RS_Ver;
StayFD _n_RS_Ver = {&RS_Ver,0,0,0,CLS_S,0,"RS_Ver","Версия формата обмена"};
StayFD *_RS_Ver = &_n_RS_Ver;

WORD  RS_State;
StayFD _n_RS_State = {&RS_State,0,0,0,CLS_I,0,"RS_State","Код состояния"};
StayFD *_RS_State = &_n_RS_State;

short RS_Answer;
StayFD _n_RS_Answer = {&RS_Answer,0,0,0,CLS_Is,0,"RS_Answer","Код ответа"};
StayFD *_RS_Answer = &_n_RS_Answer;

char RS_Message[251];
StayFD _n_RS_Message = {&RS_Message,0,0,0,CLS_V,250,"RS_Message","Сообщение о ошибке"};
StayFD *_RS_Message = &_n_RS_Message;

WORD  RS_Raj;
StayFD _n_RS_Raj = {&RS_Raj,0,0,0,CLS_I,0,"RS_Raj","Номер района"};
StayFD *_RS_Raj = &_n_RS_Raj;

DWORD RS_Nls;
StayFD _n_RS_Nls = {&RS_Nls,0,0,0,CLS_L,0,"RS_Nls","Номер лицевого"};
StayFD *_RS_Nls = &_n_RS_Nls;

char RS_PrntSName[26];
StayFD _n_RS_PrntSName = {&RS_PrntSName,0,0,0,CLS_V,25,"RS_PrntSName","Фамилия заявителя"};
StayFD *_RS_PrntSName = &_n_RS_PrntSName;

char RS_PrntMName[26];
StayFD _n_RS_PrntMName = {&RS_PrntMName,0,0,0,CLS_V,25,"RS_PrntMName","Имя заявителя"};
StayFD *_RS_PrntMName = &_n_RS_PrntMName;

char RS_PrntLName[26];
StayFD _n_RS_PrntLName = {&RS_PrntLName,0,0,0,CLS_V,25,"RS_PrntLName","Отчество заявителя"};
StayFD *_RS_PrntLName = &_n_RS_PrntLName;

char RS_PId[11];
StayFD _n_RS_PId = {&RS_PId,0,0,0,CLS_V,10,"RS_PId","Налоговый номер заявителя"};
StayFD *_RS_PId = &_n_RS_PId;

BYTE  RS_PasspType;
StayFD _n_RS_PasspType = {&RS_PasspType,0,0,0,CLS_S,0,"RS_PasspType","Тип паспорта заявителя 1 старый, 2 новый"};
StayFD *_RS_PasspType = &_n_RS_PasspType;

char RS_PaspSN[26];
StayFD _n_RS_PaspSN = {&RS_PaspSN,0,0,0,CLS_V,25,"RS_PaspSN","Серия Номер паспорта"};
StayFD *_RS_PaspSN = &_n_RS_PaspSN;

StayDate RS_PaspDt;
StayFD _n_RS_PaspDt = {&RS_PaspDt,0,0,0,CLS_Date,0,"RS_PaspDt","Дата выдачи паспорта"};
StayFD *_RS_PaspDt = &_n_RS_PaspDt;

StayDate RS_BirthDtP;
StayFD _n_RS_BirthDtP = {&RS_BirthDtP,0,0,0,CLS_Date,0,"RS_BirthDtP","Дата рождения заявителя"};
StayFD *_RS_BirthDtP = &_n_RS_BirthDtP;

char RS_ChldSName[26];
StayFD _n_RS_ChldSName = {&RS_ChldSName,0,0,0,CLS_V,25,"RS_ChldSName","Фамилия ребенка"};
StayFD *_RS_ChldSName = &_n_RS_ChldSName;

char RS_ChldMName[26];
StayFD _n_RS_ChldMName = {&RS_ChldMName,0,0,0,CLS_V,25,"RS_ChldMName","Имя ребенка"};
StayFD *_RS_ChldMName = &_n_RS_ChldMName;

char RS_ChldLName[26];
StayFD _n_RS_ChldLName = {&RS_ChldLName,0,0,0,CLS_V,25,"RS_ChldLName","Отчество ребенка"};
StayFD *_RS_ChldLName = &_n_RS_ChldLName;

StayDate RS_BirthDtC;
StayFD _n_RS_BirthDtC = {&RS_BirthDtC,0,0,0,CLS_Date,0,"RS_BirthDtC","Дата рождения ребенка"};
StayFD *_RS_BirthDtC = &_n_RS_BirthDtC;

char RS_SvidSN[26];
StayFD _n_RS_SvidSN = {&RS_SvidSN,0,0,0,CLS_V,25,"RS_SvidSN","Серия номер свидетельства о рождении ребенка"};
StayFD *_RS_SvidSN = &_n_RS_SvidSN;

StayDate RS_SvidDt;
StayFD _n_RS_SvidDt = {&RS_SvidDt,0,0,0,CLS_Date,0,"RS_SvidDt","Дата выдачи свидет о рожден"};
StayFD *_RS_SvidDt = &_n_RS_SvidDt;

WORD  RS_Insp;
StayFD _n_RS_Insp = {&RS_Insp,0,0,0,CLS_I,0,"RS_Insp","Код инспектора"};
StayFD *_RS_Insp = &_n_RS_Insp;

char RS_InspFio[51];
StayFD _n_RS_InspFio = {&RS_InspFio,0,0,0,CLS_V,50,"RS_InspFio",""};
StayFD *_RS_InspFio = &_n_RS_InspFio;

StayDate RS_CreateDt;
StayFD _n_RS_CreateDt = {&RS_CreateDt,0,0,0,CLS_Date,0,"RS_CreateDt","Дата формирования запроса"};
StayFD *_RS_CreateDt = &_n_RS_CreateDt;

/* End FCfield */
/* Begin FCextern */
extern StayDataset _n_B_JsonDndAns;
/* End FCextern */
/* Begin FCdataset */
static StayFD *tcm_B_JsonDndAns[] =
{
 (StayFD *)&_n_RS_Ver,
 (StayFD *)&_n_RS_State,
 (StayFD *)&_n_RS_Answer,
 (StayFD *)&_n_RS_Message,
 (StayFD *)&_n_RS_Nls,
 (StayFD *)&_n_RS_Raj,
 (StayFD *)&_n_RS_PrntSName,
 (StayFD *)&_n_RS_PrntMName,
 (StayFD *)&_n_RS_PrntLName,
 (StayFD *)&_n_RS_PId,
 (StayFD *)&_n_RS_PasspType,
 (StayFD *)&_n_RS_PaspSN,
 (StayFD *)&_n_RS_PaspDt,
 (StayFD *)&_n_RS_BirthDtP,
 (StayFD *)&_n_RS_ChldSName,
 (StayFD *)&_n_RS_ChldMName,
 (StayFD *)&_n_RS_ChldLName,
 (StayFD *)&_n_RS_BirthDtC,
 (StayFD *)&_n_RS_SvidSN,
 (StayFD *)&_n_RS_SvidDt,
 (StayFD *)&_n_RS_Insp,
 (StayFD *)&_n_RS_InspFio,
 (StayFD *)&_n_RS_CreateDt,
 NULL
};
StayDataset _n_B_JsonDndAns = {NULL,TAG_DATASET,0,0,DS_BBASE,0,1,0,NULL,tcm_B_JsonDndAns,NULL,
"WORK:JSONDNDANS.DT",NULL,NULL,"B_JsonDndAns",0};
StayDataset *B_JsonDndAns = &_n_B_JsonDndAns;

/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */
/* End FCframe */
/* Begin FCtabl */
void *JSONDNDANS[] =
 {NULL,
  &_nn_JSONDNDANS,
  &_n_RS_Ver,
  &_n_RS_State,
  &_n_RS_Answer,
  &_n_RS_Message,
  &_n_RS_Raj,
  &_n_RS_Nls,
  &_n_RS_PrntSName,
  &_n_RS_PrntMName,
  &_n_RS_PrntLName,
  &_n_RS_PId,
  &_n_RS_PasspType,
  &_n_RS_PaspSN,
  &_n_RS_PaspDt,
  &_n_RS_BirthDtP,
  &_n_RS_ChldSName,
  &_n_RS_ChldMName,
  &_n_RS_ChldLName,
  &_n_RS_BirthDtC,
  &_n_RS_SvidSN,
  &_n_RS_SvidDt,
  &_n_RS_Insp,
  &_n_RS_InspFio,
  &_n_RS_CreateDt,
  (StayFD *)B_JsonDndAns,
  NULL};

PICMODULEEND(JSONDNDANS)

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
