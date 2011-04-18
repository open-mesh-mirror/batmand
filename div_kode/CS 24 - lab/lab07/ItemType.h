// The following declarations and definitions go into file 
// ItemType.h. 

#include <iostream>
const int MAX_ITEMS = 100;
enum RelationType  {LESS, GREATER, EQUAL};

class ItemType 
{ 
public:
  ItemType();
  RelationType ComparedTo(ItemType) const;
  void Print(std::ostream &) const;
  void Initialize(int number);
private:
  int value;
};
 
