#include <iostream>
#include <cstdlib>
#include <sys/time.h>
#include "sortedArray.h"

using namespace std;

void PrintList(SortedType list);
SortedType QuickSort(SortedType list);

int main(int argc, char* argv[]){

  ItemType item1, item2, item3, item4, item5, item6, item7, item8, item9, item10;
  item1.Initialize(5);
  item2.Initialize(8);
  item3.Initialize(2);
  item4.Initialize(10);
  item5.Initialize(52);
  item6.Initialize(59);
  item7.Initialize(75);
  item8.Initialize(18);
  item9.Initialize(28);
  item10.Initialize(35);
  
  SortedType list, list2;
  list.Append(item1);
  list.Append(item2);
  list.Append(item3);
  list.Append(item4);
  list.Append(item5);
  
  list2.Append(item6);
  list2.Append(item7);
  list2.Append(item8);
  list2.Append(item9);
  list2.Append(item10);
  
  list.Concatenate(list2);
  
  cout << "LIST        = ";
  PrintList(list);
  
  cout << endl;
  
  list = QuickSort(list);
  
  cout << "SORTED LIST = ";
  PrintList(list);

  return 1;
}

void PrintList(SortedType list){
  list.ResetList();
  for (int i = 0; i < list.GetLength(); i++){
    ItemType item;
    list.GetNextItem(item);
    item.Print(cout);
    cout << " ";
  }
  cout << endl;
  list.ResetList();
}


SortedType QuickSort(SortedType list) {

  if (list.GetLength() <= 1) {
	cout << "Basecase" << endl;
	PrintList(list);
	return list;
  }

  SortedType listSmaller, listGreater, result, smaller, greater;
  ItemType pivot;
  int i;
  
  pivot = list.GetItem((list.GetLength())/2-1);
  list.DeleteItem(pivot);
  cout << endl <<"list = ";
  PrintList(list);
  
  for(i=0; i<list.GetLength(); i++) {
    if( list.GetItem(i).ComparedTo(pivot) == GREATER ) {
      listGreater.Append(list.GetItem(i));
    } else {
      listSmaller.Append(list.GetItem(i));
    }
  }
  
  cout << "PIVOT       = ";
  pivot.Print(cout);
  cout << endl <<"listSmaller = ";
  PrintList(listSmaller);
  cout << "listGreater = ";
  PrintList(listGreater);
  cout << endl;

  cout << "QuickSort(listSmaller)" << endl;
  listSmaller.Append(pivot);

  smaller = QuickSort(listSmaller);
  cout << "QuickSort(listGreater)" << endl;
  greater = QuickSort(listGreater);
  
  result.Concatenate(smaller);
//  result.Append(pivot);
  result.Concatenate(greater);

  return result;
  
}
