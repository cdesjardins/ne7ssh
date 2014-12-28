# Compile using GNU G++

all: passwordAuth.o keyAuth.o generateKeys.o getFile.o sftpExample.o multipleThreads.o

passwordAuth.o: passwordAuth.cpp
	g++ -c passwordAuth.cpp -o passwordAuth.o
	g++ passwordAuth.o -lnet7ssh -lbotan -o passwordAuth

keyAuth.o: keyAuth.cpp
	g++ -c keyAuth.cpp -o keyAuth.o
	g++ keyAuth.o -lnet7ssh -lbotan -o keyAuth

generateKeys.o: generateKeys.cpp
	g++ -c generateKeys.cpp -o generateKeys.o
	g++ generateKeys.o -lnet7ssh -lbotan -o generateKeys

getFile.o: getFile.cpp
	g++ -c getFile.cpp -o getFile.o
	g++ getFile.o -lnet7ssh -lbotan -o getFile

sftpExample.o: sftpExample.cpp
	g++ -c sftpExample.cpp -o sftpExample.o
	g++ sftpExample.o -lnet7ssh -lbotan -o sftpExample

multipleThreads.o: multipleThreads.cpp
	g++ -c multipleThreads.cpp -o multipleThreads.o
	g++ multipleThreads.o -lnet7ssh -lbotan -o multipleThreads
