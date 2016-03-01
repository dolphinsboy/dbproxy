MYSQL_INCLUDE=/home/guosong/mysql5627/include
MYSQL_LIB=/home/guosong/mysql5627/lib

array.o:array.h array.c
	gcc -g -c array.c

sha1.o: sha1.h sha1.c
	gcc -g -c sha1.c

passwd.o:passwd.h  passwd.c
	gcc -g -c passwd.c 

connect_mysql:connect_mysql.c array.o passwd.o sha1.o
	gcc -g -c connect_mysql.c -I $(MYSQL_INCLUDE) -L $(MYSQL_LIB) -lmysqlclient
	gcc -o connect_mysql connect_mysql.o array.o passwd.o sha1.o

clean:
	rm -rf *.o
	rm -rf connect_mysql
