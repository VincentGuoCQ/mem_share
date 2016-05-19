CC=gcc
mempool_Objects=mempoolcli.o mempoolcmd.o

mempool_Depdents=mempoolcmd.h debug.h errors.h mempoolcmn.h msgfmt.h 

mempool_Target=mempool_client

all:$(mempool_Target)

$(mempool_Target):$(mempool_Objects) $(mempool_Depdents)
	$(CC) -o $(mempool_Target) $(mempool_Objects)

mempoolcmd.o:mempoolcmd.c
	$(CC) -c mempoolcmd.c

clean:
	rm *.o
