LIB= -lpthread -ldl  -lm 

FLAG=-DVERSION="\"1.3.2.1\""

INCLUDE=-I . -I glib-2.14.0-bin/include/glib-2.0 -I glib-2.14.0-bin/lib/glib-2.0/include -I zookeeper/include/c-client-src
LIB_PATH=-L zookeeper/lib

objects= dbproxy.c  array.c  config.c Epoll.c log.c network.c password.c glib-2.14.0-bin/lib/libglib-2.0.a zookeeper/lib/libzookeeper_mt.a jansson/lib/libjansson.a

dbproxy : $(objects)
	gcc $(FLAG) -g -o dbproxy -Wall  $(objects) $(LIB_PATH) $(LIB) $(INCLUDE)
	rm -rf ./output
	mkdir -p ./output/dbproxy/{log,bin,conf}
	mv ./dbproxy ./output/dbproxy/bin/
	cp -r ./conf/* ./output/dbproxy/conf/

.PHONY : clean
clean:
	-rm -f dbproxy
	-rm -rf ./output

