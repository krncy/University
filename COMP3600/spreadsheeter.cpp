#include <iostream>
#include <fstream>
#include <vector>
#include <math.h> 
#include <random>
#include <algorithm>
#include <chrono>

#define numberOfBuckets 797
#define maxNumberOfRows 250000
#define maxNumberOfCols 1750
#define HT "\t"

using namespace std;

//random number generator
std::random_device rd;
std::mt19937 generator(rd());

//object creation count used for hashing rows
int objCount = 0;

//colour enum to colour RB-tree nodes. 
enum Colour {RED, BLACK};

class Row {
	
	//vector to store values;
	vector<int> values;
	//salt represnets a unique value to ensure hash is unique
	int salt;
	
	public:
		
		//constructor function to reserve the number of columns
		Row(int salt) {
			values.reserve(maxNumberOfCols);
			this->salt = salt;
		}
		
		//code to add an int into the values vector
		//checks to see if its beyond its maximum size
		bool addValue(int value) {
			if (values.size() < maxNumberOfCols) {
				values.push_back(value);
				return true;
			} else {
				return false;
			}
		}
		
		//change an int in the values vector
		bool modifyValue(int col, int value) {
			//if an invalid column (i.e. to big) do nothing
			if (col > values.size()) {
				return false;
			} else {
				values[col] = value;
				return true;
			}
		}
		
		//remove an int from values and shift the other values backwards.
		bool removeCol(int col) {
			if (col < values.size()) {
				values.erase(values.begin()+col);
				return true;
			}else {
				return false;
			}
		}
		
		//see if this row contain a certain int
		bool containsValue(int value) {
			for (int i = 0; i < values.size(); i++) {
				if (value == values[i]) {
					return true;
				}
			}
			return false;
		}
			
		//conver the row to something which can be printed
		string toString() {
		
			string output;
			
			for (int i = 0; i < values.size(); i++) {
				output = output + to_string(values[i]) +  "   " + HT ;
			}
			return output;
		}
		
		//helper functions
		vector<int> getValues() {
			return values;
		}
		
		//the hash just returns the salt as its guarentted to be unique and evenly distributred (provided the number of buckets << total number of rows)
		double getHash() {
			return salt;
		}
};


//Node class to store a tree
class Node {
	int key;
	Row *value;
	
	Node *parent = nullptr;
	Node *lchild = nullptr;
	Node *rchild = nullptr;
	
	Colour colour = RED;
	
	public:	
		Node(Node * parent, int key, Row * value) {
			this->key = key;
			this->value = value;
			this->parent = parent;
		}
		
		bool addElement(int key, Row *value) {
			
			//cannot store duplicate keys, so if it finds the same key already inserted, dont do anything
			if (this->key == key) {
				return false;
			}
			
			//if the key to insert is bigger than the current key, insert the key on the right child
			if (this->key < key) {
				
				//if there is no right child, make a new one and recolour the tree.
				if (rchild == nullptr) {
					rchild = new Node(this, key, value);
					repairTree(this);
					return true;
				//if there is a right child, try insert the key into the child node.
				} else {
					return rchild->addElement(key, value);
				}
			}
			
			//if the key to insert is small than the current key, isnert it into the left child
			if (key < this->key) {
				if (lchild == nullptr) {
					lchild = new Node(this, key, value);
					repairTree(this);
					return true;
				} else {
					return lchild->addElement(key, value);
				}
			}
			
			//this line can never be reached, but was included to make the compiler happy about always returning a value from a non-void function
			return false;
		}
		
		//recursivley go through the nodes going left or right depending on if the value of the current key is bigger than or smaller than the key you are looking for
		//once found, return a pointer to the row (if no row is found, return a nullptr)
		Row * findElement(int key) {
			
			if (this->key == key) {
				return value;
			} 

			if (this->key < key) {
				if (rchild != nullptr) {
					return rchild->findElement(key);
				}
				else {
					return nullptr;
				}
			} 

			if (key < this->key) {
				if (lchild != nullptr) {
					return lchild->findElement(key);
				}
				else {
					return nullptr;
				}
			}
			return nullptr;
		}
		
		bool deleteElement(int key) {
			//find the key which matches the node to be deleted
			if (this->key == key) {
				delete value;
				
				//deleting the root node is handled inside the Tree class, and hence return false here as it doesnt need to be delt with.
				if (parent == nullptr) {
					return false;
				}
				
				//find if this node is a left child or a right child 
				if (parent->lchild != nullptr) { 
					if (parent->lchild->key == key) {
						//we are therefore a left node
						
						//if there are no children, nothing has to be re-inserted.
						if (rchild == nullptr && lchild == nullptr) {
							parent->lchild = nullptr;
						}
						//if there is only one child we can set the child of out parent to be our only child
						else if (rchild == nullptr) {
							parent->lchild = lchild;
							return true;
						} else if (lchild == nullptr) {
							parent->lchild = rchild;
							return true;
						} 
						//if there are two children, choose one of the children (r child) to be the child of our parent
						//it the follows that the other child (l child) is less than every value in the rchild (definition of a binary tree)
						//and hence must be added to the left most node possible to ensure order is kept.
						else {
							parent->lchild = rchild;
							return rchild->addNodeL(lchild);
						}
					}
				}
				//very similar to above, but with the assumuption this node is a left child
				if (parent->rchild != nullptr) {
					if (parent->rchild->key == key) {
						if (rchild == nullptr && lchild == nullptr) {
							parent->rchild = nullptr;
						}
						else if (rchild == nullptr) {
							parent->rchild = lchild;
							return true;
						} else if (lchild == nullptr) {
							parent->rchild = rchild;
							return true;
						} else {
							parent->rchild = rchild;
							return rchild->addNodeL(lchild);
						}
					}
				}
				
				return true;
			} 
			
			//if the key isnt the one we are looking form recursivley look for the key.
			if (this->key < key) {
				if (rchild != nullptr) {
					return rchild->deleteElement(key);
				}
				else {
					return false;
				}
			} 

			if (key < this->key) {
				if (lchild != nullptr) {
					return lchild->deleteElement(key);
				}
				else {
					return false;
				}
			}
			return false;
		}
		
		//used to insert a child node when its parent was deleted, Adds a node to the left most child of each node.
		bool addNodeL(Node * node) {
			if (lchild == nullptr) {
				lchild = node;
				return true;
			}
			else {
				return lchild->addNodeL(node);
			}
			return false;
		}
		
		//print the node and all its subnodes (used for debug)
		string collapseNode() {
			string out = "(";
				
			if (lchild == nullptr) {
				out += "N ";
			} else {
				out += lchild->collapseNode();
			}
				
			out += to_string(key);
			
			if (rchild == nullptr) {
				out += " N";
			} else {
				out += rchild->collapseNode();
			}
			
			out += ")";
			
			return out;
		}

		int getKey() {return key;}
		Row * getValue() {return value;}
		Node * getParent() {return parent;}
		Node * getLchild() {return lchild;}
		Node * getRchild() {return rchild;}
		Colour getColour() {return colour;}
		
		void recolour(Colour c) {
			colour = c;
		}
		
		//https://en.wikipedia.org/wiki/Red%E2%80%93black_tree#Operations
		//code adapted from this wikipedia article
		Node * getSibling() {
			if (parent == nullptr) {
				return nullptr;
			} else {
				if (this == parent->lchild) {
					return rchild;
				} else {
					return lchild;
				}
			}
		}
		
		void rotateLeft() {
			Node* nnew = rchild;
			Node* p = parent;
			
			rchild = nnew->lchild;
			nnew->lchild = this;
			parent = nnew;
			
			if (rchild != nullptr) {
				rchild->parent = this;
			}
			
			if (p != nullptr) {
				if (this == p->lchild) {
					p->lchild = nnew;
				} 
				else if (this == p->rchild) {
					p->rchild = nnew;
				}
			}
			nnew->parent = p;
		}
		
		void rotateRight() {
			Node* nnew = lchild;
			Node* p = parent;
			
			lchild = nnew->rchild;
			nnew->rchild = this;
			parent = nnew;
			
			if (lchild != nullptr) {
				lchild->parent = this;
			}
			
			if (p != nullptr) {
				if (this == p->lchild) {
					p->lchild = nnew;
				} 
				else if (this == p->rchild) {
					p->rchild = nnew;
				}
			}
			nnew->parent = p;
		}

		void repairTree(Node * n) {
			if (n->getParent() == nullptr) {
				n->recolour(BLACK);
			}else if (n->getParent()->getColour() == BLACK) {
				//do nothing
			} else if (n->getParent()->getSibling() != nullptr && n->getParent()->getSibling()->getColour() == RED) {
				
				n->getParent()->recolour(BLACK);
				n->getParent()->getSibling()->recolour(BLACK);
				n->getParent()->getParent()->recolour(RED);
				repairTree(n->getParent()->getParent());
			} else {
				Node *p = n->getParent();
				Node *g = p->getParent();
				
				if (n == p->getRchild() && p == g->getLchild()) {
					p->rotateLeft();
					n = n->getLchild();
				} else if (n == p->getLchild() && p == g->getRchild()) {
					p->rotateRight();
					n = n->getRchild();
				}
				
				p = n->getParent();
				g = p->getParent();
				
				if (n == p->getLchild()) {
					g->rotateRight();
				} else {
					g->rotateLeft();
				}
				p->recolour(BLACK);
				g->recolour(RED);
			}
		}
};

//class to wrap the top most node in the tree with
//handles creating the first node (which lacks parents) and deleting said node.
class Tree {
	Node *root = nullptr;
	public:
		bool addElement(int key, Row * value) {
			if (root == nullptr) {
				root = new Node(nullptr, key,value);
				root->recolour(BLACK);
				return true;
			} else {
				return root->addElement(key,value);
			}
		}
		
		Row * findElement(int key) {
			return root->findElement(key);
		}
		
		bool deleteElement(int key) {
			if (root->getKey() == key) {
				if (root->getRchild() == nullptr && root->getLchild() == nullptr) {
					root = nullptr;
					return true;
				}
				else if (root->getRchild() == nullptr) {
					root = root->getLchild();
					return true;
				} 
				else if (root->getLchild() == nullptr) {
					root = root->getRchild();
					return true;
				} 
				else {
					Node *lc = root->getLchild();
					root = root->getRchild();
					return root->addNodeL(lc);
				}
			} 
			else if (root->getKey() < key) {
				if (root->getRchild() != nullptr) {
					return root->deleteElement(key);
				} else {
					return false;
				}
			} else if (root->getKey() > key) {				
				if (root->getLchild() != nullptr) {
					return root->deleteElement(key);
				} else {
					return false;
				}
			}
			return false;
		}
				
		Node * getRoot() {
			return root;
		}
};

//tree implementation of map
class Map {
	
	//an array of trees
	Tree buckets[numberOfBuckets];
		
	public:
		
		//find which tree the value belongs to, and add it to it.
		bool addElement(int key, Row *value) {
			int bucket = key % numberOfBuckets;
			return buckets[bucket].addElement(key, value);
		}
		
		//find which tree the value should belong to, and try and find it.
		Row * getValue(int key) {
			int bucket = key % numberOfBuckets;
			return buckets[bucket].findElement(key);
		}
		
		bool deleteElement(int key) {
			int bucket = key % numberOfBuckets;
			return buckets[bucket].deleteElement(key);
		}
		
		//prints all the trees and collapses them into a readable form - used for debugging
		void printMap() {
			for (int i = 0; i < numberOfBuckets; i++) {
				if (buckets[i].getRoot() != nullptr) {
					cout << "Bucket " << i << " contains: " << buckets[i].getRoot()->collapseNode() << endl;
				} else {
					cout << "Bucket " << i << " is empty" << endl;
				}
			}
		}
};

//global variables
//stores column names
vector<string> headerNames;
//stores all the keys stored in the map
vector<int> keyValues;
//map of values
Map values;
//stores a subsection of the keys to be shown to the user
vector<int> valuesToShow;

//function declerations
bool parse(string);

void readFile(string);
void saveFile(string);
void printHeaders();
void displayAllRows();
void displaySelection();
void sort(vector<int>&, int);
void trackRow(int);
void untrackRow(int);
void findValue(vector<int>&, int);
void addRow(int);
void addCol(int);
void deleteRow(int);
void deleteCol(int);
void editCell(int, int, int);

void randQuickSort(vector<int>&, int, int, int);
int randPartition(vector<int>&, int, int, int);
int partition(vector<int>&, int, int, int);


int main() {
	//reserve space for vectors (up to the maximum sizes made in report) (declared at the top of the program as constants)
	headerNames.reserve(maxNumberOfCols);
	keyValues.reserve(maxNumberOfRows);
	valuesToShow.reserve(maxNumberOfRows);
	
    cout << "Please open a file with \"open <filename.txt>\", or add a row or column with \"add row {value}\" and \"add column [name]\"" << endl;
	
	//poll the user for a command
	string command;
	while (getline(cin, command)) {
		
		//try and parse the command
		if (!parse(command)) {
			cout << "I don't understand that command" << endl;
		}
	}
}

//print the column names
void printHeaders() {
	for (int i = 0; i < headerNames.size(); i++) {
		cout << headerNames[i] << "   " << HT;
	}
	cout << endl;
}

bool parse(string command) {
	//timing for you to complete a single task
	auto t1 = std::chrono::high_resolution_clock::now();
	
	//all these follow the same structure
		//check if the inputed string by the user matches the name of a command
		//if it does, extract the arguments
		//pass the values into the corresponding functions
	if ("open" == command.substr(0, 4)) {
		string path = command.substr(5);
		readFile(path);
	}
	else if ("save" == command.substr(0,4)) {
		string path = command.substr(5);
		saveFile(path);
	}
	else if ("display all" == command.substr(0,11)) {
		displayAllRows();
	}
	else if ("display selection" == command.substr(0,17)) {
		displaySelection();
	}
	else if ("sort all" == command.substr(0,8)) {
		int col = stoi(command.substr(9));
		if (col < headerNames.size()) {
			sort(keyValues, col);
			cout << "all rows sorted" << endl;
		} else {
			cout << "error" << endl;
		}
	}
	else if ("sort selection" == command.substr(0,14)) {
		int col = stoi(command.substr(15));
		if (col < headerNames.size()) {
			sort(valuesToShow, col);
			displaySelection();
		} else {
			cout << "error" << endl;
		}
	}
	else if ("track rows" == command.substr(0,10)) {
		string input = command.substr(11);
		int start;
		int stop;
		for (int i = 0; i < input.length(); i++) {
			if (!isdigit(input.at(i))) {
				start = stoi(input.substr(0,i));
				stop = stoi(input.substr(i+1));
				break;
			} 
		}
		
		if (start < stop && stop < keyValues.size()) {
		
			for (int i = start; i <= stop; i++) {
				trackRow(i);
			}
			displaySelection();
		} else {
			cout << "error" << endl;
		}
	}
	else if ("track row" == command.substr(0,9)) {
		int row = stoi(command.substr(10));
		
		if (row < keyValues.size()) {
			trackRow(row);
			displaySelection();
		} else {
			cout << "error" << endl;
		}
	}
	else if ("untrack rows" == command.substr(0,12)) {
	string input = command.substr(13);
		int start;
		int stop;
		for (int i = 0; i < input.length(); i++) {
			if (!isdigit(input.at(i))) {
				start = stoi(input.substr(0,i));
				stop = stoi(input.substr(i+1));
				break;
			} 
		}
		
		if (start < stop && stop < valuesToShow.size()) {
		
			for (int i = start; i <= stop; i++) {
				untrackRow(i);
			}
			displaySelection();
		} else {
			cout << "error" << endl;
		}
	}
	else if ("untrack row" == command.substr(0,11)) {
		int row = stoi(command.substr(12));
		
		if (row < valuesToShow.size()) {
			untrackRow(row);
			displaySelection();
		} else {
			cout << "error" << endl;
		}
	}
	else if ("find" == command.substr(0,4)) {
		int value = stoi(command.substr(5));
		findValue(keyValues, value);
	}
	else if ("edit header" == command.substr(0,11)) {
		string input = command.substr(12);
		int col;
		string name;
		
		for (int i = 0; i < input.length(); i++) {
			if (!isdigit(input.at(i))) {
				col = stoi(input.substr(0,i));
				name = input.substr(i+1);
				break;
			} 
		}
		
		if (col >= 0 && col < headerNames.size()) {
			headerNames[col] = name;
			printHeaders();
		} else {
		cout << "error!" << endl;
		}
	}
	else if ("add row" == command.substr(0,7)) {		
		int input = stoi(command.substr(8));
		addRow(input);
	}
	else if ("add column" == command.substr(0,10)) {
		int input = stoi(command.substr(11));
		addCol(input);
	}
	else if ("delete row" == command.substr(0,10)) {
		int row = stoi(command.substr(11));
		deleteRow(row);	
	}
	else if ("delete column" == command.substr(0,13)) {
		int col = stoi(command.substr(14));
		deleteCol(col);
	}
	else if ("edit cell" == command.substr(0,9)) {
		string str = command.substr(10);
		
		int row;
		int col;
		int change;
		
		for (int i = 0; i < str.length(); i++) {
			if (!isdigit(str.at(i))) {
				row = stoi(str.substr(0,i));
				str = str.substr(i+1);
				break;
			} 
		}
		
		for (int i = 0; i < str.length(); i++) {
			if (!isdigit(str.at(i))) {
				col = stoi(str.substr(0,i));
				str = str.substr(i+1);
				break;
			} 
		}
		change = stoi(str);

		editCell(row, col, change);

	}
	else if ("print map" == command.substr(0,9)) {
		values.printMap();
	}
	else {
		//no match found - unable to process
		return false;
	}
	
	auto t2 = std::chrono::high_resolution_clock::now();
		
	std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count()<< " milliseconds\n";
	//This returns true if any of the commands match
	return true;
}

void readFile(string filename) {
	
	//clear all the values, and reset the values to their initial values
	//this does not clear out the memory and creates a massive memory leak as the rows and or nodes are not deleted properly
	//i could not get garbage deletion working
	headerNames.clear();
	keyValues.clear();
	values = Map();
	valuesToShow.clear();
	objCount = 0;
	
	//open the file and extract the data
	ifstream inputFile(filename);
	
	int numCol;
	int numRow;
	
	inputFile >> numCol >> numRow;

	string temp;
	for (int i = 0; i < numCol; i++) {
		inputFile >> temp;
		headerNames.push_back(temp);
	}
	
	for (int i = 0; i < numRow; i++) {
		//create a row object
		Row *row = new Row(objCount++);
		
		//Push the inputed values into it
		for (int j = 0; j < numCol; j++) {
			inputFile >> temp;
			row->addValue(stoi(temp));
		}
		
		//add the hash of the row to the keyValues array so it can be found later
		keyValues.push_back(row->getHash());
		//add the key-value pair to the values map
		values.addElement(row->getHash(), row);
	}
	inputFile.close();
}

void saveFile(string filename) {
	
	//open the file and put all the data into the file
	ofstream file(filename);
	
    file << headerNames.size() << endl;
	file << keyValues.size() << endl;

    for (int i = 0; i < headerNames.size(); i++) {
        file << headerNames[i] << endl;
    }
	
	for (int i = 0; i < keyValues.size(); i++) {
		Row r = *values.getValue(keyValues[i]);
		for (int j = 0; j < r.getValues().size(); j++) {
			file << r.getValues()[j] << endl;
		}
	}
	
    file.close();
}

void displayAllRows() {
	if (keyValues.size() != 0) {
		//print headers
		cout << HT;
		printHeaders();
	
		//output each row
		for (int i = 0; i < keyValues.size(); i++) {
			cout << i << HT << (*values.getValue(keyValues[i])).toString() << endl;
		}
	} else {
		cout << "Please add some rows" << endl;
	}
}

void displaySelection() {
	if (valuesToShow.size() != 0) {
		//print headers
		cout << HT;
		printHeaders();
		
		//output each row
		for (int i = 0; i < valuesToShow.size(); i++) {
			cout << i << HT << (*values.getValue(valuesToShow[i])).toString() << endl;
		}
	} else {
		cout << "Please track some rows between rows 0 and " << keyValues.size() - 1 << endl;
	}
}

void trackRow(int row) {
	//check that the row is not already tracked
	if (find(valuesToShow.begin(), valuesToShow.end(), keyValues[row]) == valuesToShow.end()) {
		//add it to the array which has the keys which are being tracked
		valuesToShow.push_back(keyValues[row]);
	}
}

void untrackRow(int row) {
	//remove an element from the valuesToShow list at index row
	valuesToShow.erase(valuesToShow.begin() + row);
}

void sort(vector<int> & values, int col) {
	if (col > headerNames.size()) {
		cout << "Column enterd invalid" << endl;
	} else {
		//initiate the sort 
		randQuickSort(values, 0, values.size() - 1, col);
	}
}

void findValue(vector<int> & arr, int value) {
	
	//print the headers with a tab before
	cout << endl << HT;
	printHeaders();
	
	//print loop through all the values in the keyValue list, get the row, and see if it contains the value
	//if it does, print the row
	for (int i = 0; i < arr.size(); i++) {
		if (values.getValue(arr[i])->containsValue(value)) {
			cout << i << HT << values.getValue(arr[i])->toString() << endl;
		}
	}
}

void addRow(int defaultValue) {
	//if you have not reached the row limit
	if (keyValues.size() < maxNumberOfRows) {
		
		//creat a new row object and fill it with the default value
		Row row (objCount++);
		for (int i = 0; i < headerNames.size(); i++) {
			row.addValue(defaultValue);
		}
		
		//hash the object, and add it the keyValues array so it can be referenced later and add it to the map
		keyValues.push_back(row.getHash());
		values.addElement(row.getHash(), &row);	
	}
}

void addCol(int defaultValue) {
	//check youre not at the limit of columns
	if (headerNames.size() < maxNumberOfCols) {
		//add the header name to the header list (default of Col"i")
		headerNames.push_back("Col" + to_string(headerNames.size() + 1));
		//go through each row and add the default value to each row
		for (int i = 0; i < keyValues.size(); i++) {
			values.getValue(keyValues[i])->addValue(defaultValue);
		}
	}	
}

void deleteRow(int row) {
	//check the row exists
	if (row < keyValues.size()) {
		//remove the value from the map
		values.deleteElement(keyValues[row]);
		
		//remove the value from the current rows being tracked if it is being tracked
		for (int i = 0; i < valuesToShow.size(); i++) {
			if (valuesToShow[i] = keyValues[row]) {
				valuesToShow.erase(valuesToShow.begin() + i);
				break;
			}
		}
		
		//remove it from all the keys 
		keyValues.erase(keyValues.begin() + row);
	}
}

void deleteCol(int col) {
	//check the column exists
	if (col < headerNames.size()) {
		//loop through all the rows, and remove the value at the index corresponding to the column.
		for (int i = 0; i < keyValues.size(); i++) {
				values.getValue(keyValues[i])->removeCol(col);
		}
		//remove the header
		headerNames.erase(headerNames.begin() + col);
	}
}

void editCell(int row, int col, int value) {
	//if the row and column are within the bounds of rows and columns that exist
	if (row < keyValues.size() && col < headerNames.size()) {
		//go to the row and update the value in the cell
		values.getValue(keyValues[row])->modifyValue(col, value);
	}
}
//-------------------------------SORTING-------------------------------//
void randQuickSort(vector<int> &rows, int p, int r, int col) {
	if (p < r) {
		int q = randPartition(rows, p, r, col);
		randQuickSort(rows, p, q-1, col);
		randQuickSort(rows, q+1, r, col);
	}
}

int randPartition(vector<int> &rows, int p, int r, int col) {
	//generate random number between p and r inclusive and store it in i
	uniform_int_distribution<int> distr(p, r);
	int i = distr(generator);
	
	int temp = rows[i];
	rows[i] = rows[r];
	rows[r] = temp;
	
	return partition(rows,p,r,col);
}

int partition(vector<int> &rows, int p, int r, int col) {

	int temp;
	//get the value to sort against from the map
	int x = values.getValue(rows[r])->getValues()[col];
	int i = p - 1;

	for (int j = p; j <= r-1; j++) {
		//get the value to sort against from the map
		if (values.getValue(rows[j])->getValues()[col] < x) {
			i++;
			temp = rows[i];
			rows[i] = rows[j];
			rows[j] = temp;
		}
	}
	temp = rows[i+1];
	rows[i+1] = rows[r];
	rows[r] = temp;
	return i+1;
}