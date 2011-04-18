#include "UnsortedType.h"


using namespace std;

void PrintList(UnsortedType&);

void Test1() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh;
  obj.Initialize(1);
  objLow.Initialize(4);
  objHigh.Initialize(8);
  obj2.Initialize(2);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(12);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  ut.GetItemsInRange(newList, objLow, objHigh);
  
  std::cout << "Test 1:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: <no values> - Result: ";
  PrintList(newList);
}

void Test2() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh;
  obj.Initialize(1);
  objLow.Initialize(1);
  objHigh.Initialize(12);
  obj2.Initialize(2);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(12);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  ut.GetItemsInRange(newList, objLow, objHigh);
  
  std::cout << "Test 2:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 1 12 2 10 11 - Result: ";
  PrintList(newList);
}

void Test3() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh;
  obj.Initialize(1);
  objLow.Initialize(1);
  objHigh.Initialize(2);
  obj2.Initialize(3);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(12);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  ut.GetItemsInRange(newList, objLow, objHigh);
  
  std::cout << "Test 3:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 1 - Result: ";
  PrintList(newList);
}

void Test4() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh;
  obj.Initialize(1);
  objLow.Initialize(12);
  objHigh.Initialize(13);
  obj2.Initialize(3);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(13);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  ut.GetItemsInRange(newList, objLow, objHigh);
  
  std::cout << "Test 4:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 13 - Result: ";
  PrintList(newList);
}

void Test5() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh, obj6DEL;
  obj.Initialize(1);
  objLow.Initialize(12);
  objHigh.Initialize(13);
  obj2.Initialize(3);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(13);
  obj6DEL.Initialize(10);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj6DEL);

  
  std::cout << "Test 5:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 11 3 13 1 - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

void Test6() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, objLow, objHigh, obj6DEL;
  obj.Initialize(1);
  objLow.Initialize(12);
  objHigh.Initialize(13);
  obj2.Initialize(3);
  obj3.Initialize(10);
  obj4.Initialize(11);
  obj5.Initialize(13);
  obj6DEL.Initialize(15);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj6DEL);

  
  std::cout << "Test 6:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 11 10 3 13 1 - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

void Test7() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5;
  obj.Initialize(1);
  obj2.Initialize(2);
  obj3.Initialize(3);
  obj4.Initialize(4);
  obj5.Initialize(5);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj);
  newList.InsertItem(obj5);
  newList.InsertItem(obj2);
  newList.InsertItem(obj3);
  newList.InsertItem(obj4);
  
  
  std::cout << "Test 7:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: <no values> - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

void Test8() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, obj6DEL, obj7DEL, obj8DEL, obj9DEL, obj10DEL;
  obj.Initialize(1);
  obj2.Initialize(2);
  obj3.Initialize(3);
  obj4.Initialize(4);
  obj5.Initialize(5);
  obj6DEL.Initialize(1);
  obj7DEL.Initialize(6);
  obj8DEL.Initialize(7);
  obj9DEL.Initialize(8);
  obj10DEL.Initialize(9);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj6DEL);
  newList.InsertItem(obj7DEL);
  newList.InsertItem(obj8DEL);
  newList.InsertItem(obj9DEL);
  newList.InsertItem(obj10DEL);
  
  
  std::cout << "Test 8:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 4 5 2 3 - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

void Test9() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, obj6DEL, obj7DEL, obj8DEL, obj9DEL, obj10DEL;
  obj.Initialize(1);
  obj2.Initialize(2);
  obj3.Initialize(3);
  obj4.Initialize(4);
  obj5.Initialize(5);
  obj6DEL.Initialize(5);
  obj7DEL.Initialize(6);
  obj8DEL.Initialize(7);
  obj9DEL.Initialize(8);
  obj10DEL.Initialize(9);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj6DEL);
  newList.InsertItem(obj7DEL);
  newList.InsertItem(obj8DEL);
  newList.InsertItem(obj9DEL);
  newList.InsertItem(obj10DEL);
  
  
  std::cout << "Test 9:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect: 4 3 2 1 - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

void Test10() {
  UnsortedType ut, empty;
  UnsortedType newList;
  ItemType obj, obj2, obj3, obj4, obj5, obj6DEL, obj7DEL, obj8DEL, obj9DEL, obj10DEL;
  obj.Initialize(1);
  obj2.Initialize(2);
  obj3.Initialize(3);
  obj4.Initialize(4);
  obj5.Initialize(5);
  obj6DEL.Initialize(3);
  obj7DEL.Initialize(6);
  obj8DEL.Initialize(7);
  obj9DEL.Initialize(8);
  obj10DEL.Initialize(9);
  ut.InsertItem(obj);
  ut.InsertItem(obj5);
  ut.InsertItem(obj2);
  ut.InsertItem(obj3);
  ut.InsertItem(obj4);
  newList.InsertItem(obj6DEL);
  newList.InsertItem(obj7DEL);
  newList.InsertItem(obj8DEL);
  newList.InsertItem(obj9DEL);
  newList.InsertItem(obj10DEL);
  
  
  std::cout << "Test 10:\nInitial List: ";
  PrintList(ut);
  std::cout << "Expect:  4 2 5 1 - Result: ";
  ut.DeleteItemsFromList(newList);
  PrintList(ut);
}

int main()
{
	int number;
	UnsortedType rangeList,list;
	ItemType item;
	
	while (number != -1){
		cout << "Please enter a number to insert, -1 to stop: ";
		cin >> number;
		
		if (number != -1){
			item.Initialize(number);
			list.InsertItem(item);
		}
	}	
	PrintList(list);
	
	ItemType low, high;
	int val;
	cout<< "Please enter a low range: ";
	cin >> val;	
	low.Initialize(val);
	cout << "Please enter a high range: ";
	cin >> val;
	high.Initialize(val);
	list.GetItemsInRange(rangeList, low, high);
	PrintList(rangeList);
	list.DeleteItemsFromList(rangeList);
	PrintList(list);
	Test1();
	Test2();
	Test3();
	Test4();
	Test5();
	Test6();
	Test7();
	Test8();
	Test9();
	Test10();
	cout << "\nThe time complexity of GetItemsInRange is O(n) because it has one loop where it iterates through all elements.\n";
	cout << "\nThe time complexity of DeleteItemsFromList is O(2n^2) because it has a loop that iterates through all elements and then calls RetrieveItem() and DeleteItem() which both also runs through the whole list of elements - O(n(n+n)) = O(2n^2).\n";
	return 0;
}

void PrintList(UnsortedType& list){
  int length;
  ItemType item;

  list.ResetList();
  length = list.GetLength();
  for (int counter = 1; counter <= length; counter++){
    list.GetNextItem(item);
    item.Print(cout);
  }
  list.ResetList();
  cout << endl;
}
