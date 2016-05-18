CC=gcc
vmem_Objects=vmemcli.o vmemcmd.o 

vmem_Depdents=vmemcmd.h debug.h errors.h vmemcmn.h climsgfmt.h 

vmem_Target=vmem_client

vmem_Test=vmem_test

all:$(vmem_Target)

test:$(vmem_Test)

$(vmem_Target):$(vmem_Objects) $(vmem_Depdents)
	$(CC) -o $(vmem_Target) $(vmem_Objects)

vmemcli.o:vmemcli.c
	$(CC) -c vmemcli.c
vmemcmnd.o:vmemcmd.c
	$(CC) -c vmemcmd.c
vmem_test.o:vmem_test.c
	$(CC) -c vmem_test.c
$(vmem_Test):vmem_test.o
	$(CC) -o $(vmem_Test) vmem_test.o
clean:
	rm *.o
