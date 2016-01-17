tst_sniffer: sniffer.c tst_sniffer.c tcpipproto.c
	gcc -g -o $@ $^

clean:
	rm -f tst_sniffer *.o
