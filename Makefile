ALL:
	g++ -o main \
	main.cpp \
	./source/Crypto.cpp \
	-g3 -O2 -Wall -Wextra -l:libcryptopp.a