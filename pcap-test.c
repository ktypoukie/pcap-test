#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

struct MAChdr{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct IPhdr{
	uint8_t data[12];
	uint8_t src[4];
	uint8_t dst[4];
};

struct TCPhdr{
	uint8_t src[2];
	uint8_t dst[2];
	uint8_t data[16];
};

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		struct MAChdr* MACheader;
		struct IPhdr* IPheader;
		struct TCPhdr* TCPheader;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		if(header->caplen < sizeof(struct MAChdr)) continue;
		MACheader = (struct MAChdr*)packet;
		if(ntohs(MACheader->type) != 0x0800){
			printf("EtherType is not IPv4(EtherType: %04x)",ntohs(MACheader->type));
			continue;
		}

		if(header->caplen < sizeof(struct MAChdr) + sizeof(struct IPhdr)) continue;
		IPheader = (struct IPhdr*)(packet + sizeof(struct MAChdr));
		uint8_t IPlen = (IPheader->data[0]) & 0x0F;
		
		if(header->caplen < sizeof(struct MAChdr) + IPlen*4 + sizeof(struct TCPhdr)) continue;
		TCPheader = (struct TCPhdr*)(packet + sizeof(struct MAChdr) + IPlen*4);
		uint8_t TCPlen = ((TCPheader->data[8]) & 0xF0) >> 4;

		if(header->caplen < sizeof(struct MAChdr) + IPlen*4 + TCPlen*4) continue;
		uint32_t Datalen = (header->caplen) - (sizeof(struct MAChdr) + IPlen*4 + TCPlen*4);
		if(Datalen > 20) Datalen = 20;
		const uint8_t *Data = packet + sizeof(struct MAChdr) + IPlen*4 + TCPlen*4;

		printf("dst mac: ");
		for(int i=0;i<6;i++) printf("%02x ",MACheader->dst[i]);
		printf("\nsrc mac: ");
		for(int i=0;i<6;i++) printf("%02x ",MACheader->src[i]);		
		printf("\n");

		printf("src ip: ");
		for(int i=0;i<4;i++) printf("%02x ",IPheader->src[i]);
		printf("\ndst ip: ");
		for(int i=0;i<4;i++) printf("%02x ",IPheader->dst[i]);
		printf("\n");

		printf("src port: ");
		for(int i=0;i<2;i++) printf("%02x ",TCPheader->src[i]);
		printf("\ndst port: ");
		for(int i=0;i<2;i++) printf("%02x ",TCPheader->dst[i]);
		printf("\n");

		printf("Payload Data: ");
		for(int i=0;i<Datalen;i++) printf("%02x ",Data[i]);
		printf("\n\n");
	}

	pcap_close(pcap);
}
