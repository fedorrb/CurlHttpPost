#ifndef NORMALIZE_H
#define NORMALIZE_H
#include <cstdlib>
#include <string>
#include <list>
#include <fstream>
#include <iostream>
#include <sstream>
#include <locale>
//#include <codecvt>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;
/*
класс для форматирования текста входного файла
настроен на формат файлов обмена через сокет
*/

class Normalize
{
public:
	Normalize(void);
	void SetFileName(string fileName);
	void CreateNewFileName(string fileName = "");
	bool LoadFile();
	void SaveFile();
	void SplitStringLine(std::string& str, std::vector<std::string> & cont); //функция разбивки одной строки на несколько по разделителю
	void ModifyLengthCol(std::vector<std::string> & cont); //форматирование колонок
public:
	~Normalize(void);
private:
	string fileName;
	std::vector<std::string> splitContents; //массив в который считывается исходный файл с разделением на строки
	void GetMasLengthCurStr(std::string str, std::vector<int> &strLengthMas); //получение ширины колонок
	void MergeMas(std::vector<int> &blockLengthMas, std::vector<int> &strLengthMas); //из полученой ширины колонок и текущей оставить наибольшие
	void ModifyLengthBlockCol(std::vector<std::string> &cont, std::vector<int> &blockLengthMas, int cur, int amount); //изменить ширину колонок
};
#endif