core = obj/crc32.o obj/md5.o obj/md4.o

none :

mac-all : clean-mac mactest

mactest : bin/mactest

bin/mactest : $(core) obj/mactest.o
	clang -Wall $(core) obj/mactest.o -o bin/mactest

clean-mac :
	rm -f obj/*
	rm -f bin/*

obj/mactest.o : macmain.c
	clang -c -Wall macmain.c -o obj/mactest.o

obj/crc32.o : core/crc32.c core/crc32.h
	clang -c -Wall -fPIC core/crc32.c -o obj/crc32.o

obj/md4.o : core/md4.c core/md4.h
	clang -c -Wall -fPIC core/md4.c -o obj/md4.o

obj/md5.o : core/md5.c core/md5.h
	clang -c -Wall -fPIC core/md5.c -o obj/md5.o
