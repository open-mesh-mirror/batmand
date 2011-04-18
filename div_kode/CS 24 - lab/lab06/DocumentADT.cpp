//Submitted by Marianne Bohler and Espen Graarud

#include "DocumentADT.h"

DocumentADT::DocumentADT(){}

void DocumentADT::InsertDoc(Document d){
	docList.push_back(d);
}

void DocumentADT::Print(){
	for (int i = 0; i < docList.size(); i++)
		docList[i].Print();
}
