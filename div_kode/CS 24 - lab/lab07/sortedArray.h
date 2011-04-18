#include "ItemType.h" 


class SortedType 
{
public:
  SortedType();

  void MakeEmtpy(); 
  bool IsFull() const;
  int GetLength() const;
  void RetrieveItem(ItemType& item, bool& found);
  void InsertItem(ItemType item);
  void DeleteItem(ItemType item);
  void ResetList();
  void GetNextItem(ItemType& item);
  void MakeEmpty();
  
  ItemType GetItem(int index);
  void Append(ItemType item);
  void Concatenate(SortedType list);
  
  SortedType QuickSort(SortedType list);

private:
  int length;
  ItemType info[MAX_ITEMS];
  int currentPos;
};

