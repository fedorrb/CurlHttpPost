//#include "StdAfx.h"
#include "Normalize.h"

Normalize::Normalize(void)
{
	splitContents.clear();
	fileName.clear();
}

Normalize::~Normalize(void)
{
}

void Normalize::SetFileName(string fileName)
{
	this->fileName = fileName;
}

void Normalize::CreateNewFileName(string fileName)
{
	if(fileName.size())
	{
		this->fileName = fileName;
	}
	else
	{
		size_t end = this->fileName.find_last_of(".");
		if(end != string::npos)
		{
			this->fileName = this->fileName.substr(0, end) + "_S.TXT";
		}
	}
}
//прочитать файл,
//разбить на строки по разделителю,
//записать в вектор строк,
//отформатировать ширину колонок
bool Normalize::LoadFile()
{
	bool result = false;
	size_t pos = 0;
	if(fileName.length() > 3) {
		ifstream bmFile;
		bmFile.open(fileName.c_str());
		string str;
		if(bmFile.is_open()) {
			while(getline(bmFile, str))
			{
				SplitStringLine(str, splitContents);
			}
			result = true;
			bmFile.close();
			ModifyLengthCol(splitContents);
		}
	}
	return result;
}

void Normalize::SaveFile()
{
	ofstream bmFile;
	bmFile.open(fileName.c_str());
	vector<string>::iterator it;
	for (it = splitContents.begin(); it != splitContents.end(); ++it)
	{
		bmFile << (*it) << endl;
	}
	bmFile.flush();
	bmFile.close();
}
//функция разбивки одной строки на несколько по разделителю
void Normalize::SplitStringLine(std::string& str, std::vector<std::string> & cont)
{
    std::size_t current, previous = 0;
	string delims = "{";
	current = str.find(delims, previous);
    while (current != std::string::npos) {
		if(current > 0)
			if(previous > 0)
				cont.push_back(str.substr(previous-1, current-(previous-1)) + '\n');
			else
				cont.push_back(str.substr(0, current) + '\n');
		previous = (current + 1);
		current = str.find(delims, previous);
    }
	if(previous > 0)
		cont.push_back(str.substr(previous-1));
	else
		cont.push_back(str.substr(0));
}
//форматирование колонок
void Normalize::ModifyLengthCol(std::vector<std::string> &cont)
{
	int amount, cur = 0;
	int sizeMas = cont.size();
	vector<int> blockLengthMas;
	vector<int> strLengthMas;
	blockLengthMas.clear();
	for(cur = 0; cur < sizeMas; cur++)
	{
		strLengthMas.clear();
		GetMasLengthCurStr(cont[cur], strLengthMas);
		if(strLengthMas.size() > 0)
		{
			if(strLengthMas.size() == blockLengthMas.size())
			{
				MergeMas(blockLengthMas, strLengthMas);
				amount++;
			}
			else
			{
				if(blockLengthMas.size())
					ModifyLengthBlockCol(cont, blockLengthMas, cur, amount);
				blockLengthMas.clear();
				MergeMas(blockLengthMas, strLengthMas);
				amount = 1;
			}
		}
		else
		{
			if(blockLengthMas.size() > 1) {
				ModifyLengthBlockCol(cont, blockLengthMas, cur, amount);
			}
			blockLengthMas.clear();
			amount = 0;
		}
	}
}
//получение ширины колонок в заданной строке
//можно переписать на поиск парных "
void Normalize::GetMasLengthCurStr(std::string str, std::vector<int> &strLengthMas)
{
	std::string delims = "\",\"";
	std::size_t current, previous = 0;
	std::size_t lengthDelim = delims.length();
	int numCol = 0;
	current, previous = 0;
	current = str.find(delims);
	numCol = 0;
	while (current != std::string::npos) {
		if(numCol >= strLengthMas.size())
			strLengthMas.push_back(current - previous);
		else {
			if((current - previous) > strLengthMas[numCol])
				strLengthMas[numCol] = (current - previous);
		}
		previous = (current + lengthDelim);
		current = str.find(delims, previous);
		numCol++;
	}
}
//из полученой ширины колонок текущей строки и текущего блока строк оставить наибольшие
void Normalize::MergeMas(std::vector<int> &blockLengthMas, std::vector<int> &strLengthMas)
{
	int sizeBlockMas = blockLengthMas.size();
	int sizeStrMas = strLengthMas.size();
	if(sizeBlockMas < sizeStrMas)
	{
		blockLengthMas.resize(sizeStrMas, 0);
		sizeBlockMas = blockLengthMas.size();
	}
	for(int i = 0; i < sizeBlockMas; i++)
	{
		if(i >= sizeStrMas)
			break;
		if(blockLengthMas[i] < strLengthMas[i])
			blockLengthMas[i] = strLengthMas[i];
	}
}
//изменить ширину колонок
//вход:
//cont - вектор строк (всех)
//blockLengthMas - вектор с шириной колонок
//cur - курсор (текущая позиция в векторе строк)
//amount - количество строк которые обрабатываются (текущая не обрабатываеся, только amount предыдущих)
void Normalize::ModifyLengthBlockCol(std::vector<std::string> &cont, std::vector<int> &blockLengthMas, int cur, int amount)
{
	std::string delims = "\",\"";
	std::size_t current, previous = 0;//позиции в строке
	std::size_t lengthDelim = delims.length();
	int start = cur - amount; //позиции в массиве
	int delta = 0;
	int numCol = 0;
	if(start >= 0)
	{
		for (int i = start; i < cur; i++)
		{
			current, previous = 0;
			current = cont[i].find(delims);
			numCol = 0;
			while (current != std::string::npos) {
				if(numCol < blockLengthMas.size()) {
					delta = blockLengthMas[numCol] - (current - previous);
					if(delta > 0) {
						cont[i].insert(current, delta, ' ');
						current += delta;
					}
				}
				previous = (current + lengthDelim);
				current = cont[i].find(delims, previous);
				numCol++;
			}
		}
	}
}