BitCreator:	*.cpp *.h *.hpp
	g++ -I. -Wunused -Wunreachable-code -Wall -std=c++11 -lgmpxx -lgmp *.cpp -o BitCreator
