#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <byteswap.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#define FINFLAG 1
#define SYNFLAG 2
#define RESFLAG 4
#define ACKFLAG 16
 
FILE *fopen64(const char *filename, const char *mode);

void read_gen_headers(FILE *__fd){

	struct pcap_header *pcap_General;


	pcap_General = (struct pcap_header*)malloc(sizeof(struct pcap_header));    
	fread(pcap_General, sizeof(struct pcap_header), 1, __fd); 

  (pcap_General->magic_number);
	if (pcap_General->magic_number == 2712847316u ){
		bigEndian = 1;
	}
	else{
		bigEndian=0;
	}
	
	pcap_General->magic_number =fix_end32(pcap_General->magic_number);
	pcap_General->version_major = fix_end16 (pcap_General->version_major);
	pcap_General->version_minor = fix_end16 (pcap_General->version_minor);

	pcap_General->sigfigs = fix_end16 (pcap_General->sigfigs);
	pcap_General->snaplen = fix_end16 (pcap_General->snaplen);
	pcap_General->network = fix_end16 (pcap_General->network);
	free(pcap_General);


}

void set_flags( struct flow_rec *__flow_rec){
	if (FINFLAG & __flow_rec->Flags[1]){
		__flow_rec->FIN = 1;	
	}
	else{
		__flow_rec->FIN = 0;			
	}

	if (SYNFLAG & __flow_rec->Flags[1]){
		__flow_rec->SYN = 1;	
	}
	else{
		__flow_rec->SYN = 0;			
	}

	if (RESFLAG & __flow_rec->Flags[1]){
		__flow_rec->RES = 1;	
	}
	else{
		__flow_rec->RES = 0;			
	}

	if (ACKFLAG & __flow_rec->Flags[1]){
		__flow_rec->ACK = 1;	
	}
	else{
		__flow_rec->ACK = 0;			
	}
}

void read_payload(FILE *__fd, int size,	struct flow_rec *__flow_rec){
	char *_raw = (char *)malloc(size); 
	char *_IP_raw;
	fread(_raw, size, 1, __fd); 
	__flow_rec->macSrc->B1 = *_raw;
	__flow_rec->macSrc->B2 = *(_raw+1);
	__flow_rec->macSrc->B3 = *(_raw+2);
	__flow_rec->macSrc->B4 = *(_raw+3);
	__flow_rec->macSrc->B5 = *(_raw+4);
	__flow_rec->macSrc->B6 = *(_raw+5);

	__flow_rec->macDst->B1 = *(_raw+6);
	__flow_rec->macDst->B2 = *(_raw+7);
	__flow_rec->macDst->B3 = *(_raw+8);
	__flow_rec->macDst->B4 = *(_raw+9);
	__flow_rec->macDst->B5 = *(_raw+10);
	__flow_rec->macDst->B6 = *(_raw+11);

	__flow_rec->EthType[0] = *(_raw+12);
	__flow_rec->EthType[1] = *(_raw+13);

	if (__flow_rec->EthType[0] == 8 && __flow_rec->EthType[1] ==0 ){
		_IP_raw = _raw+14;
		__flow_rec->Vlantag[0] = '\0';
		__flow_rec->Vlantag[1] = '\0';
		}
	else if (__flow_rec->EthType[0] == 129 && __flow_rec->EthType[1] ==0 ){
		__flow_rec->Vlantag[0] = *(_raw+14);
		__flow_rec->Vlantag[1] = *(_raw+15);
		__flow_rec->EthType[0] = *(_raw+16);
		__flow_rec->EthType[1] = *(_raw+17);
		_IP_raw = _raw+18;
	}
 else{
   return;
 }
 
		__flow_rec->IPTOS = *(_IP_raw+1);
		__flow_rec->IPProto = *(_IP_raw+9);
		
		__flow_rec->IPSrc->B1 = *(_IP_raw+12);	
		__flow_rec->IPSrc->B2 = *(_IP_raw+13);
		__flow_rec->IPSrc->B3 = *(_IP_raw+14);
		__flow_rec->IPSrc->B4 = *(_IP_raw+15);

		__flow_rec->IPDst->B1 = *(_IP_raw+16);
		__flow_rec->IPDst->B2 = *(_IP_raw+17);
		__flow_rec->IPDst->B3 = *(_IP_raw+18);
		__flow_rec->IPDst->B4 = *(_IP_raw+19);
		
		if ((__flow_rec->IPProto == 6) || (__flow_rec->IPProto == 17)){
			__flow_rec->SrcPort[0] = *(_IP_raw+20);
			__flow_rec->SrcPort[1] = *(_IP_raw+21);
			__flow_rec->DstPort[0] = *(_IP_raw+22);
			__flow_rec->DstPort[1] = *(_IP_raw+23);
			if (__flow_rec->IPProto ==6){
				__flow_rec->Flags[0] = *(_IP_raw+32);
				__flow_rec->Flags[1] = *(_IP_raw+33);
				set_flags(__flow_rec);
			}
		}
   free(_raw);
   
	
}

void  read_packet_header(FILE *__fd, struct pcap_record* __rec_header, 
	struct flow_rec *__flow_rec){
  
	__rec_header->ts_sec =  fix_end32(__rec_header->ts_sec);
	__rec_header->ts_usec =  fix_end32(__rec_header->ts_usec);
  __rec_header->incl_len =  fix_end32(__rec_header->incl_len);
	__rec_header->orig_len =  fix_end32(__rec_header->orig_len);

	__flow_rec->macSrc = (struct mac*)malloc(sizeof(struct mac)); 
	__flow_rec->macDst = (struct mac*)malloc(sizeof(struct mac)); 

	__flow_rec->IPSrc = (struct IP*)malloc(sizeof(struct IP)); 
	__flow_rec->IPDst = (struct IP*)malloc(sizeof(struct IP));

	read_payload(__fd, __rec_header->orig_len, __flow_rec);
}

void print_flow_rec(struct flow_rec *__flow_rec, int __row, int __sec, int __usec){

	int holder;
	printf("%d", __row);
	printf(",");
	printf("%d",__sec);
	printf(",");
	printf("%d", __usec);
	printf(",");
		
	printf("%d", (unsigned char)__flow_rec->macSrc->B1);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macSrc->B2);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macSrc->B3);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macSrc->B4);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macSrc->B5);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macSrc->B6);
	printf(",");


	printf("%d", (unsigned char)__flow_rec->macDst->B1);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macDst->B2);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macDst->B3);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macDst->B4);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macDst->B5);
	printf(",");
	printf("%d", (unsigned char)__flow_rec->macDst->B6);
	printf(",");

		
	printf("%02x", (unsigned char)__flow_rec->Vlantag[0]);
	printf("%02x", (unsigned char)__flow_rec->Vlantag[1]);
	printf(",");
	printf("%02x", (unsigned char)__flow_rec->EthType[0]);
	printf("%02x", (unsigned char)__flow_rec->EthType[1]);
	

	
	if (__flow_rec->EthType[0] == 8 && __flow_rec->EthType[1] ==0 ) {

		printf(",");
		printf("%02d", (unsigned char)__flow_rec->IPSrc->B1);
		printf(",");
		printf("%02d", (unsigned char)__flow_rec->IPSrc->B2);
		printf(",");
		printf("%02d", (unsigned char)__flow_rec->IPSrc->B3);
		printf(",");
		printf("%02d", (unsigned char)__flow_rec->IPSrc->B4);

		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPDst->B1);
		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPDst->B2);
		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPDst->B3);
		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPDst->B4);
		
		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPProto);
		printf(",");
		printf("%d", (unsigned char)__flow_rec->IPTOS);
		if ((__flow_rec->IPProto == 6) || (__flow_rec->IPProto == 17)){
			printf(",");
			holder = (unsigned char)__flow_rec->SrcPort[0];
			printf("%d", holder*256+(unsigned char)__flow_rec->SrcPort[1]);	
			

			printf(",");
			holder = (unsigned char)__flow_rec->DstPort[0];
			printf("%d", holder*256+(unsigned char)__flow_rec->DstPort[1]);			
			if (__flow_rec->IPProto == 6){
				printf(",");
				printf("%d", (unsigned char)__flow_rec->FIN);
				printf(",");
				printf("%d", (unsigned char)__flow_rec->SYN);
				printf(",");
				printf("%d", (unsigned char)__flow_rec->RES);
				printf(",");
				printf("%d", (unsigned char)__flow_rec->ACK);
				//printf("%02x", (unsigned char)__flow_rec->Flags[0]);
				//printf("%02x", (unsigned char)__flow_rec->Flags[1]);
			}
			else{
				printf(",0");
				printf(",0");
				printf(",0");
				printf(",0");
			}
		}
		else{
			printf(",0");		
			printf(",0");
			printf(",0");
			printf(",0");
			printf(",0");
			printf(",0");
		}
	}

	else{
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
		printf(",0");
	
	}

	
	printf("\n");
}

int get_fd(FILE **__fd, char * __path){

 FILE *fd;
	 *__fd=fopen64(__path, "r");
   if (__fd ==NULL){
     return 1;
   }
   else{
     return 0;
   }
   
}

void print_headers(){
	printf("Row,time,time_u,SM1,SM2,SM3,SM4,SM5,SM6,DM1,DM2,DM3,DM4,DM5,DM6,");
	printf("VlanTag_X,EthType_X,SIP1,SIP2,SIP3,SIP4,DIP1,DIP2,DIP3,DIP4,IPProto,");
	printf("IPTos,SrcPort,DstPort,FIN,SYN,RES,ACK\n");
}

//Input format: <Executable> <input file>
int main(int argc, char *argv[]){
	FILE *fd;
	int i;
	int read_bytes;
  char *_line;
   size_t *_n;
	if (argc < 2){
		printf("Input format: <Executable> <input file>\n");
     return 1;
	}
  
  if(get_fd(&fd, argv[1])){
    printf("unable to open file\n");
    printf("Error %d \n", errno);
    return 1;
  }
  read_bytes = 1;
  _line = (char *) malloc(sizeof(char)*10000);
  read_bytes = getline(_line, _n, fd);
  printf(read_bytes);
  
 /* while(read_bytes >0){
  	
   read_packet_header(fd, rec_header, _flow_rec);
    
    if (i ==1){
      Base = 	0;//(rec_header->ts_sec);
      Base_u = 0;//	(rec_header->ts_usec);
    }
    
    print_flow_rec(_flow_rec, i, rec_header->ts_sec-Base, rec_header->ts_usec-Base_u);
    free(_flow_rec->macSrc);
    free(_flow_rec->macDst);
    free(_flow_rec->IPSrc);
    free(_flow_rec->IPDst);
 //free(_flow_rec);
    i++;

    //
    if (i==1907833){
      j = 4;
    }
    
    	read_bytes = fread(rec_header, sizeof(struct pcap_record), 1, fd); 
    
  }*/
  
  fclose(fd);
	
}
