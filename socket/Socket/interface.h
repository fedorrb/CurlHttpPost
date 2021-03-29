#define Visible 1
#define NoVisible 0

short SetItemText(StayWindow * Wnd,WORD ID, char* Text);

short SetWndText(StayWindow * Wnd, char* Text);

// переотображение компонента окна
//Wnd - идентификатор окна  ID - Ай-Ди компонента
short ItemShow(StayWindow * Wnd,WORD ID);
//Флаг = 1 - Отобразить 0 - скрыть
short ItemVisible(StayWindow * Wnd,WORD ID, short Flag);
//eустановка фокуса
short SetItemFocus(StayWindow * Wnd,WORD ID);


BYTE	Find_Context(StayDataset *Base, StayEvent s, StayFD* FindName,char *Str);