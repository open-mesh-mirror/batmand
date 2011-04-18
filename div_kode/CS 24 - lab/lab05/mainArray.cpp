#include <iostream>
#include <cstdlib>
#include <sys/time.h>
#include "sortedArray.h"

using namespace std;

double CalcMillis(struct timeval, struct timeval);
void PrintList(SortedType list);

int main(int argc, char* argv[]){
	SortedType list;
	int toInsert;
        static struct timeval startTime, endTime, startAll;
	double timePassed;
	
	if (argc == 2){
		toInsert = atoi(argv[1]);
	}else{
		cout << "usage: progname number " << endl;
		return 0;
	}	
	
       	gettimeofday(&startTime, NULL);
	gettimeofday(&startAll, NULL);
	
	for(int i = 0; i < toInsert; i++){
		ItemType item;
		item.Initialize(i);
		list.InsertItem(item);
	}
	
        gettimeofday(&endTime, NULL);
	
	timePassed = CalcMillis(startTime, endTime);
	
	cout << "It has taken " << timePassed << " seconds to insert all the items." << endl;
	
        gettimeofday(&startTime, NULL);
	
	for(int i = 0; i < toInsert; i++){
		ItemType item;
		bool in;
		item.Initialize(i);
		list.RetrieveItem(item, in);
	}
	
        gettimeofday(&endTime, NULL);
        
	timePassed = CalcMillis(startTime, endTime);
	
	cout << "It has taken " << timePassed << " seconds to retrieve all the items." << endl;
	
	gettimeofday(&startTime, NULL);
	
	for(int i = 0; i < toInsert; i++){
		ItemType item;
		item.Initialize(i);
		list.DeleteItem(item);
	}
	
	gettimeofday(&endTime, NULL);
        
	timePassed = CalcMillis(startTime, endTime);
        
	cout << "It has taken " << timePassed << " seconds to delete all the items." << endl;
	
	timePassed = CalcMillis(startAll, endTime);
 	
	cout << "It has taken " << timePassed << " seconds total." << endl;
	
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

double CalcMillis(struct timeval start, struct timeval end){
	double startTime = (double)start.tv_usec/1000000;
	double endTime = (end.tv_sec - start.tv_sec) + (double)end.tv_usec/1000000;
	
	return endTime - startTime;
}
