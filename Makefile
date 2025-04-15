C11 = -std=c++11
C17 = -std=c++17

all:tmp 

.PHONY:tmp

tmp:tmp.cpp 
	g++ -g -o tmp tmp.cpp $(C11) -lpthread -L. net.cpp
