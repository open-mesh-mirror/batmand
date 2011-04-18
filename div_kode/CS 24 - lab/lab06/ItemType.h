//Submitted by Marianne Bohler and Espen Graarud

#include <iostream>

const int MAX_ITEMS = 100;
enum RelationType {EQUAL};

class ItemType{
	public:
		ItemType();
		RelationType ComparedTo(ItemType) const;
		void Print(std::ostream&) const;
		void Initialize(string value);
	private:
		string value;
};
