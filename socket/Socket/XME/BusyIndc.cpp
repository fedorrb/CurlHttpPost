/* Begin FCbegin */
//-------------------------------------------------------------------------
// STAY / W      Resource file BUSYINDC.XME
//-------------------------------------------------------------------------
// Created 15\12\2020 12:26
//-------------------------------------------------------------------------

#include "BUSYINDC.h"

/* End FCbegin */
/* Begin FCinclude */
#include "SERVERADDR.h"
/* End FCinclude */
/* Begin FChead */
PICMODULEBEG(BUSYINDC)

static StayFD _nn_BUSYINDC = {NULL,TAG_PIC,0,0,0,0,"BUSYINDC",NULL};
/* End FChead */
/* Begin FCtypedef */
/* End FCtypedef */
/* Begin FCfield */
/* End FCfield */
/* Begin FCextern */
extern StayWindow _n_WndBusy;
extern StayWindow _n_WndSetAddr;
/* End FCextern */
/* Begin FCdataset */
/* End FCdataset */
/* Begin FCmenu */
/* End FCmenu */
/* Begin FCframe */

IWStayWin *_init_WndBusy ()
{
 IWStayWin *item[8];
 CreateFrame ("WndBusy", 5, 5, 245, 145, STM_MODIFIED, STW_CENTER, "Триває обробка", &item[0]);
 item[0]->CreateItem ("STAYSTATIC", NULL, 39, 11, 166, 20, STM_MODIFIED, 0, 0, "З\'єднання з сервером.", NULL);
 item[0]->CreateItem ("STAYSTATIC", NULL, 42, 40, 160, 48, STM_MODIFIED, 0, 0, "Програма може деякий час не відповідати.", NULL);
 return item[0];
}
StayWindow _n_WndBusy = {NULL,TAG_FRAME,0,0,0,"WndBusy",_init_WndBusy};
StayWindow *WndBusy = &_n_WndBusy;


IWStayWin *_init_WndSetAddr ()
{
 IWStayWin *item[8];
 CreateFrame ("WndSetAddr", 63, 131, 326, 176, STM_MODIFIED, STW_CENTER, "Настройка адреси сервера", &item[0]);
 item[0]->CreateItem ("STAYEDIT", "J_SRVIP", 140, 18, 161, 18, STM_MODIFIED, 0, FLD1, "", &item[1]);
 item[1]->SetProperty ("source", (DWORD)&_n_J_SRVIP);
 item[1]->Release ();
 item[0]->CreateItem ("STAYEDIT", "J_SRVPORT", 140, 41, 161, 18, STM_MODIFIED, 0, FLD2, "", &item[1]);
 item[1]->SetProperty ("source", (DWORD)&_n_J_SRVPORT);
 item[1]->Release ();
 item[0]->CreateItem ("STAYBUTTON", NULL, 92, 107, 142, 24, STM_CLICKED, 0, BUT1, "\"Enter\" Підтвердити", NULL);
 item[0]->CreateItem ("STAYSTATIC", NULL, 22, 18, 45, 18, STM_NORMAL, 0, 0, "IP:", NULL);
 item[0]->CreateItem ("STAYSTATIC", NULL, 22, 41, 45, 18, STM_NORMAL, 0, 0, "Порт:", NULL);
 item[0]->CreateItem ("STAYBUTTON", NULL, 92, 73, 142, 24, STM_CLICKED, 0, BUT2, "Тест", NULL);
 return item[0];
}
StayWindow _n_WndSetAddr = {NULL,TAG_FRAME,0,0,0,"WndSetAddr",_init_WndSetAddr};
StayWindow *WndSetAddr = &_n_WndSetAddr;

/* End FCframe */
/* Begin FCtabl */
void *BUSYINDC[] =
 {NULL,
  &_nn_BUSYINDC,
  (StayFD *)WndBusy,
  (StayFD *)WndSetAddr,
  NULL};

PICMODULEEND(BUSYINDC)

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
