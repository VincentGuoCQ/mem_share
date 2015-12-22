CC=gcc
Target=main
Object=page_table.o main.o
Depend=page_table.h

$(Target):$(Object)
	$(CC) -o $(Target) $(Object)
page_table.o:page_table.c
	$(CC) -c page_table.c
main.o:main.c
	$(CC) -c main.c


clean:
	rm *.o
