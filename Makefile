all:
	g++ main.cpp pcap_reader.cpp codec.cpp -I . --std=c++11 -lpcap -lopus -o rtp_decoder -g
