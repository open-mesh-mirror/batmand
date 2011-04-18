// Implementation file for sorted.h

#include "sortedArray.h"
SortedType::SortedType() {
  length = 0;
}

void SortedType::MakeEmpty() {
  length = 0;
} 


bool SortedType::IsFull() const{
  return (length == MAX_ITEMS);
}

int SortedType::GetLength() const{
  return length;
}

void SortedType::RetrieveItem(ItemType& item, bool& found) {
  int midPoint;
  int first = 0;
  int last = length - 1;

  bool moreToSearch = (first <= last);
  found = false;
   while (moreToSearch && !found) {
    midPoint = ( first + last) / 2;
    switch (item.ComparedTo(info[midPoint])) {
      case LESS    : last = midPoint - 1;
                     moreToSearch = (first <= last);
                     break;
      case GREATER : first = midPoint + 1;
                     moreToSearch = (first <= last);
                     break;
      case EQUAL   : found = true;
                     item = info[midPoint];
                     break;
    }
  }
}

void SortedType::DeleteItem(ItemType item){
	int location = 0;

	while( item.ComparedTo(info[location]) != EQUAL && location < length){
		location++;
	}

	if(location != length){
		info[location] = info[length - 1];
		length--;
	}
}

void SortedType::InsertItem(ItemType item) {
  int location = 0;
  int midPoint;
  int first = 0;
  int last = length - 1;
  
  bool moreToSearch = (first <= last);
  bool found = false;

  while (moreToSearch && !found) {
    midPoint = ( first + last) / 2;
    switch (item.ComparedTo(info[midPoint])) {
      case LESS    : last = midPoint - 1;
                     moreToSearch = (first < last);
                     break;
      case GREATER : first = midPoint + 1;
                     moreToSearch = (first < last);
                     break;
    }
    if(first == last) {
      found = true;
      location = midPoint;
    }
  } 
  for (int index = length; index > location; index--)
    info[index] = info[index - 1];
  info[location] = item;
  length++;
}

void SortedType::ResetList(){
  currentPos = -1;
}

void SortedType::GetNextItem(ItemType& item) {
  currentPos++;
  item = info[currentPos];
}

ItemType SortedType::GetItem(int index) {
  return info[index];
}

void SortedType::Append(ItemType item) {
  info[length] = item;
  length++;
}

void SortedType::Concatenate(SortedType list) {
  int i;
  ItemType item;
//   list.ResetList();
  for(i=0; i<list.GetLength(); i++) {
    item = list.GetItem(i);
    info[length+i] = item;
  }
  length = length + list.GetLength();
}
