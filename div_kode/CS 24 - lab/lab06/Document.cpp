//Submitted by Marianne Bohler and Espen Graarud

#include "Document.h"
#include <iostream>

using namespace std;

Document::Document(){
	name = "";
}

void Document::InsertTermDoc(string tag){
	tags.push_back(tag);
}

void Document::Print(){
	cout << "Name: " << name << endl;
	for (int i = 0; i < tags.size(); i++)
		cout << tags[i] << " ";
	cout << endl << endl;
}

void Document::Initialize(string docName){
	name = docName;
}

bool Document::IsEmpty(){
	return (name == "");
}
	
