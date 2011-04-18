//Submitted by Marianne Bohler and Espen Graarud

#include <string>
#include <vector>

using namespace std;

class Document{
  public:
    Document();
//     ~Document();
    
    
    //Transformers
    void InsertTermDoc(string term);
    void DeleteTermDoc(string term);
    
    
    
    void Print();
    void Initialize(string docName);
    bool IsEmpty();
	
  private:
    vector<string> tags;
    string name;
	
};
