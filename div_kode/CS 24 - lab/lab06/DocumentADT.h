//Submitted by Marianne Bohler and Espen Graarud

#include "Document.h"

class DocumentADT{
  public:
    DocumentADT();
//     ~DocumentADT();
    
    //Transformers
    void EmptyDoc();
    void InsertDoc(Document doc);
    
    
    //Observers
    bool IsEmptyDoc();
    
    
    //Iterators
    void ResetDoc();
    Document GetNextDoc(Document& doc);
    vector<Document> FindDocTerm(string term);
    vector<Document> FindDocDescendantTerm(string term);
    vector<Document> FindPairs(string term); //Whats the difference between this and FindDocTerm???
    Document FindBestDoc(vector<string> term);
    
    
    void Print();
	
  private:
    vector<Document> docList;
};
