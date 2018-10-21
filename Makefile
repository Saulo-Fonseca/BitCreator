BitCreator:	BitCreator.cpp SHA256.h SHA256.cpp RIPEMD160.h RIPEMD160.cpp
	g++ -I. -Wall -std=c++11 -lgmpxx -lgmp BitCreator.cpp SHA256.cpp RIPEMD160.cpp -o BitCreator
