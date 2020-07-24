all:
	g++ -o pcap-test main.cpp pcap-test.cpp -lpcap

clean:
	rm pcap-test