#include <pcap.h>
#include <time.h>
#include <winsock.h>
#include <iostream>
#include <fstream>
// #pragma comment(lib,"ws2_32.lib")
using namespace std;

/* 4 bytes IP address */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;


//TCP首部
typedef struct tcp_header
{
	unsigned short src_port;    //源端口号   
	unsigned short dst_port;    //目的端口号   
	unsigned int seq_no;        //序列号   
	unsigned int ack_no;        //确认号      
	unsigned char reserved_1; //保留6位中的4位首部长度   
	// unsigned char thl : 4;        //tcp头部长度   
	// unsigned char flag : 6;       //6位标志   
	unsigned char reseverd_2; //保留6位中的2位   
	unsigned short wnd_size;    //16位窗口大小   
	unsigned short chk_sum;     //16位TCP检验和   
	unsigned short urgt_p;      //16为紧急指针   

}tcp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);



int ACK = 0x10;
int FIN = 0x01;

bool ethnet = true;
int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[100];
    struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);
    getchar();
    /* Check if the user specified a valid adapter */
    if (inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name, // name of the device
        65536,          // portion of the packet to capture. 
                       // 65536 grants that the whole packet will be captured on all the MACs.
        1,              // promiscuous mode (nonzero means promiscuous)
        1000,           // read timeout
        errbuf          // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        ethnet = false;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;

    cout<<"please enter the filter: ";
    cin.getline(packet_filter, 100);
    // cout<<packet_filter<<endl;

    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}
u_int seq_pre=0;
u_int len_pre=0;
bool flag_pre = false;
// char http_header[1460];
/* Callback function invoked by libpcap for every incoming packet */
void deal_file(){
    ifstream fin("webpage.txt");   
    char c;
    while(fin.get(c)){
        printf("%c", c);
    }
    fin.close();
}
char http_header[1460];
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    ip_header* ih;
    udp_header* uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;
    ofstream fout;
    ih = (ip_header*)(pkt_data +
        14); //length of ethernet header
    if(!ethnet) ih = (ip_header*)(pkt_data+4);
    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    ip_address saddr = ih->saddr;
     (VOID)(param);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    

    /* retireve the position of the ip header */
    
    tcp_header* th = (tcp_header*)((u_char*)ih + ip_len);
    u_short src_port = ntohs(th->src_port);
    u_short dst_port = ntohs(th->dst_port);
    u_int seq_no = ntohl(th->seq_no);
    u_int ack_no = ntohl(th->ack_no);
    // u_char thl = th->thl;
    u_char thl = th->reserved_1 & 0xf0;
    thl  = thl>>4;
    u_char reseverd_1 = th->reserved_1 & 0x0f;
    u_char flag = th->reseverd_2 & 0x3f;
    u_char reseverd_2 = th->reseverd_2 & 0xc0;

    // u_char flag = th->flag;
    bool ack = flag & ACK;
    bool fin = flag & FIN;
    
    u_short wnd_size = ntohs(th->wnd_size);
    u_short chk_sum = ntohs(th->chk_sum);
    u_short urgt_p = ntohs(th->urgt_p);
    
    u_char* http_data = (u_char*)th + thl*4;
    int head_len = 14 + ip_len + thl*4;
    int data_len = header->len - head_len;
  
    // cout << "src_port: " << src_port << endl;
    // cout << "dst_port: " << dst_port << endl;
    // cout << "seq_no: " << seq_no << endl;
    // cout << "ack_no: " << ack_no << endl;
    // printf("thl: 0x%x\n", thl);
    // printf("reserved_1: 0x%x\n", reseverd_1);
    // printf("reserved_2: 0x%x\n", reseverd_2);
    // printf("flag: 0x%x\n", flag);
    // cout << "ack: " << ack << endl;
    // cout << "fin: " << fin << endl;
    // cout << "wnd_size: " << wnd_size << endl;
    // cout << "chk_sum: " << chk_sum << endl;
    // cout << "urgt_p: " << urgt_p << endl;
    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", saddr.byte1, saddr.byte2, saddr.byte3, saddr.byte4, src_port, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dst_port);
    if((saddr.byte1 == 120 && saddr.byte2 == 48 && saddr.byte3 == 171 && saddr.byte4 == 216)) goto MUTI_FRAME;
    else if(src_port == 8083);
    else return;
    /*
     * unused parameter
     */
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
    cout<<endl;
    if(header->len <= 60) return;
    if(data_len <= 0) return;
    if(strncmp((char*) http_data, "HTTP", 4) == 0){
        int cnt = 0;
        while(strncmp((char*)http_data,"\r\n\r\n",4) != 0){
            http_header[cnt] = *http_data;
            printf("%c", *(http_data));
            cnt++;
            http_data++;
        }
        http_header[cnt] = '\0';
        http_data+=4;
        cnt+=4;
        // ofstream fout("webpage.html", ios::app);
        // fout.write((char*)http_data, data_len - cnt);
        // fout.close();
    }
    fout.open("webpage.html", ios::out);
    fout.write((char*)http_data, data_len);
    fout.close();
    if(ack&&fin){
        exit(0);
    }
    return;
MUTI_FRAME:
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
    cout<<endl;
    if(ack&&fin&&flag_pre){
        // deal_file();
        exit(0);
    }  
    if(header->len <= 60) return;
    
    cout << "head_len: " << head_len << endl;
    
    if(data_len <= 0) return;
    cout << "data_len: " << data_len << endl;
       
    if(seq_pre!=0&& seq_no!= seq_pre+len_pre){
        if(remove("webpage_new.dat")==0) cout<<"remove success!"<<endl;
        printf("wrong sequence!\n");
        exit(0);
        // exit(0);
    }
    if(strncmp((char*)http_data, "HTTP", 4) == 0){
        seq_pre = seq_no;
        int cnt = 0;
        while(strncmp((char*)http_data,"\r\n\r\n",4) != 0){
            http_header[cnt] = *http_data;
            printf("%c", *(http_data));
            cnt++;
            http_data++;
        }
        http_header[cnt] = '\0';
        http_data+=4;
        cnt+=4;
        fout.open("webpage_new.dat", ios::out|ios::binary);
        fout.write((char*)http_data, data_len - cnt);
        fout.close();
        seq_pre = seq_no;
        len_pre = data_len;
        flag_pre = true;
    }else{
        fout.open("webpage_new.dat", ios::app|ios::binary);
        fout.write((char*)http_data, data_len);
        fout.close();
        seq_pre = seq_no;
        len_pre = data_len;
        flag_pre = true;
    }
}
    

