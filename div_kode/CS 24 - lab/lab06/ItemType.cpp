//Submitted by Marianne Bohler and Espen Graarud

#include <iostream>
#include "ItemType.h"

ItemType::ItemType(){
	value = NULL;
}

RelationType ItemType::ComparedTo(ItemType otherItem) const{
	if(value == otherItem.value){
		return EQUAL;
	}
}

void ItemType::Print(std::ostream& out) const{
	out << value << " ";
}

void ItemType::Initialize(string v){
	value = v;
}
