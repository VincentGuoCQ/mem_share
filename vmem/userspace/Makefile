CC=gcc
vmem_Objects=vmemcli.o vmemcmd.o 

vmem_Depdents=vmemcmd.h debug.h errors.h vmemcmn.h msgfmt.h 

vmem_Target=vmem_client

all:$(vmem_Target)

$(vmem_Target):$(vmem_Objects) $(vmem_Depdents)
	$(CC) -o $(vmem_Target) $(vmem_Objects)

vmemcli.o:vmemcli.c
	$(CC) -c vmemcli.c
vmemcmnd.o:vmemcmd.c
	$(CC) -c vmemcmd.c

clean:
	rm *.o
