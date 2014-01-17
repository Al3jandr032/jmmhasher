core = obj/crc32.o obj/md5.o obj/md4.o obj/sha1.o

none :

mac-all : clean-mac mactest

mactest : bin/mactest

bin/mactest : $(core) obj/mactest.o
	clang -g -O0 -Wall $(core) obj/mactest.o -o bin/mactest

clean-mac :
	rm -f obj/*
	rm -f bin/*

obj/mactest.o : macmain.c
	clang -c -g -O0 -Wall macmain.c -o obj/mactest.o

obj/crc32.o : core/crc32.c core/crc32.h
	clang -c -g -O0 -Wall -fPIC core/crc32.c -o obj/crc32.o

obj/md4.o : core/md4.c core/md4.h
	clang -c -g -O0 -Wall -fPIC core/md4.c -o obj/md4.o

obj/md5.o : core/md5.c core/md5.h
	clang -c -g -O0 -Wall -fPIC core/md5.c -o obj/md5.o

obj/sha1.o : core/sha1.c core/sha1.h
	clang -c -g -O0 -Wall -fPIC core/sha1.c -o obj/sha1.o

