#include "K_pgw.h"

using namespace std;

//int num_conn;
//int max_conn;

struct thread_data{
   int id;
   int core;
   int min;
   int max;
};


struct cadata{
   int fd,num;
};

#define print_error_then_terminate(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)


//State 
unordered_map<uint32_t, uint64_t> s5_id; /* S5 UE identification table: s5_cteid_ul -> imsi */
unordered_map<string, uint64_t> sgi_id; /* SGI UE identification table: ue_ip_addr -> imsi */
unordered_map<uint64_t, UeContext> ue_ctx; /* UE context table: imsi -> UeContext */
/* IP addresses table - Write once, Read always table - No need to put mlock */ 
unordered_map<uint64_t, string> ip_addrs;

//Not needed for single core
pthread_mutex_t s5id_mux; /* Handles s5_id */
pthread_mutex_t sgiid_mux; /* Handles sgi_id */
pthread_mutex_t uectx_mux; /* Handles ue_ctx */
pthread_mutex_t listen_mux; /*handles listen_fd*/

int listen_fd;
struct sockaddr_in pgw_server_addr;

void *run(void* arg)
{

   int lsfd, acfd, portno, n, numev, ccfd, cafd, cret,trf;
   char buf[110];
   long long transactions = 0;

   int count,tcount;
   
   struct sockaddr_in server, c_addr, rcvr_addr;
   struct hostent *c_ip;
   
   set<int> srca, srcc, srcr; //set-C-accept/connect/read;
   map<int, cadata> mm;
   struct cadata cd;
   int port;

   struct thread_data *my_data;
	my_data = (struct thread_data *) arg;
	int threadID = my_data->id;
	int core_id = my_data->core;

   	//pgw specific
	uint8_t eps_bearer_id;
	uint32_t s5_uteid_ul;
	uint32_t s5_uteid_dl;
	uint32_t s5_cteid_ul;
	uint32_t s5_cteid_dl;
	uint64_t apn_in_use;
	uint64_t tai;
	string ue_ip_addr;
	uint64_t imsi;
	bool res;

	int i,returnval,cur_fd, act_type;
	map<int, mdata> fdmap;
	struct mdata fddata;
	Packet pkt;
	int pkt_len;
	char * dataptr;
	unsigned char data[BUF_SIZE];


	const pthread_t pid = pthread_self();
	cout << "pid " << pid << endl;

	// cpu_set_t: This data set is a bitset where each bit represents a CPU.
    cpu_set_t cpuset;
  

    // CPU_ZERO: This macro initializes the CPU set set to be the empty set.
    CPU_ZERO(&cpuset);
  
    // CPU_SET: This macro adds cpu to the CPU set set.
    cout << "coreid " << core_id << endl;
    CPU_SET(core_id, &cpuset);
 
    // pthread_setaffinity_np: The pthread_setaffinity_np() function sets the CPU affinity mask of the thread thread to the CPU set pointed to by cpuset. If the call is successful, and the thread is not currently running on one of the CPUs in cpuset, then it is migrated to one of those CPUs.
    const int set_result = pthread_setaffinity_np(pid, sizeof(cpu_set_t), &cpuset);
    if (set_result != 0) {
 
    print_error_then_terminate(set_result, "pthread_setaffinity_np");
    }
 
    // Check what is the actual affinity mask that was assigned to the thread.
    // pthread_getaffinity_np: The pthread_getaffinity_np() function returns the CPU affinity mask of the thread thread in the buffer pointed to by cpuset.
    const int get_affinity = pthread_getaffinity_np(pid, sizeof(cpu_set_t), &cpuset);
    if (get_affinity != 0) {
 
    print_error_then_terminate(get_affinity, "pthread_getaffinity_np");
    }




      int epfd = epoll_create(MAXEVENTS + 5);
      if( epfd == -1){
         cout<<"Error: epoll create"<<'\n';
         exit(-1);
      }

      int retval;
      struct epoll_event ev, rev[MAXEVENTS];

      pthread_mutex_lock(&listen_mux);
      ev.data.fd = listen_fd;
      ev.events = EPOLLIN;
      retval = epoll_ctl( epfd, EPOLL_CTL_ADD, listen_fd, &ev);
      pthread_mutex_unlock(&listen_mux);
      if( retval == -1) {
         cout<<"Error: epoll ctl lsfd add"<<'\n';
         exit(-1);
      }

      bzero((char *) &rcvr_addr, sizeof(rcvr_addr) );
      rcvr_addr.sin_family = AF_INET;
      rcvr_addr.sin_addr.s_addr = inet_addr("192.168.122.167");

      struct sockaddr_in from;
      bzero((char *) &from, sizeof(from) );
      socklen_t fromlen = sizeof(from);

     //cout<<"Entering Loop"<<'\n';
      count = 0;
      tcount=0;
      trf = 0;
      transactions = 0;


      while( 1 )
      {


         numev = epoll_wait( epfd, rev, MAXEVENTS, -1);
         cout << numev << endl;
         if(numev < 0)
         {
            cout<<"Error: EPOLL wait!"<<'\n';
            exit(-1);
         }

         if(numev == 0)
         {
               if(trf == 1)
               {
                  cout<<"Throughput :"<<transactions<<'\n';
                  trf = 0;
                  transactions = 0;
               }
               //cout<<"Tick "<<'\n';
         }

         for( i = 0; i < numev; i++)
         {


            trf = 1;
            //Check Errors
            if(   (rev[i].events & EPOLLERR) || (rev[i].events & EPOLLHUP)) 
            {

                  cout<<"ERROR: epoll monitoring failed, closing fd"<<'\n';
                  if(rev[i].data.fd == lsfd){
                     cout<<"Oh Oh, lsfd it is"<<'\n';
                     exit(-1);
                  }
                  close(rev[i].data.fd);
                  continue;

            }

         
         
            else if(rev[i].events & EPOLLIN)
            {                    

                  cafd = rev[i].data.fd;
         
                  pkt.clear_pkt();
                  
                  {

                        n = recvfrom(cafd, pkt.data, BUF_SIZE, 0, (struct sockaddr *) &from, &fromlen);
                        if ( n < 0) {
                          break;
                          cout<<"Error : Read Error "<<'\n';
                          exit(-1);
                        }
                        pkt.len = n;
						pkt.extract_gtp_hdr();
						if(pkt.gtp_hdr.msg_type == 1)
						{

								port = ntohs(from.sin_port);
								pkt.extract_item(s5_cteid_dl);
								cout << port << " " << s5_cteid_dl << endl;
								pkt.extract_item(imsi);
								pkt.extract_item(eps_bearer_id);
								pkt.extract_item(s5_uteid_dl);
								pkt.extract_item(apn_in_use);
								pkt.extract_item(tai);

								s5_cteid_ul = s5_cteid_dl;
								s5_uteid_ul = s5_cteid_dl;

								ue_ip_addr = ip_addrs[imsi];//locks not needed, read only

								TRACE(cout<<"3rd Attach imsi"<<imsi<<" cteid_dl "<<s5_cteid_dl<<endl;)

								pthread_mutex_lock(&s5id_mux);
								cout << "add  data to s5 "<< imsi << " " << s5_uteid_ul << endl;
								s5_id[s5_uteid_ul] = imsi;
								pthread_mutex_unlock(&s5id_mux);

								pthread_mutex_lock(&sgiid_mux);
								sgi_id[ue_ip_addr] = imsi;
								pthread_mutex_unlock(&sgiid_mux);

								pthread_mutex_lock(&uectx_mux);
								ue_ctx[imsi].init(ue_ip_addr, tai, apn_in_use, eps_bearer_id, s5_uteid_ul, s5_uteid_dl, s5_cteid_ul, s5_cteid_dl);
								pthread_mutex_unlock(&uectx_mux);

								pkt.clear_pkt();
								pkt.append_item(s5_cteid_ul);
								pkt.append_item(eps_bearer_id);
								pkt.append_item(s5_uteid_ul);
								pkt.append_item(ue_ip_addr);
								pkt.prepend_gtp_hdr(2, 1, pkt.len, s5_cteid_dl);
								rcvr_addr.sin_port = htons(port);
								cout << port << " " << "dl:" << s5_cteid_dl << endl;
		                        n = sendto(cafd, pkt.data, pkt.len, 0,(const struct sockaddr *)&rcvr_addr,sizeof(rcvr_addr));

		                        if(n <= 0){
		                           cout<<"Error : Write Error"<<'\n';
		                           exit(-1);
		                        } 
                     
                        		

		                }

		                if(pkt.gtp_hdr.msg_type == 4)
						{

								port = ntohs(from.sin_port);
								cout << port << " " << s5_cteid_dl << endl;
								TRACE(cout <<"Detach in PGW "<< pkt.gtp_hdr.teid << endl;)
								res = true;
								
								pthread_mutex_lock(&s5id_mux);
								if (s5_id.find(pkt.gtp_hdr.teid) != s5_id.end()) {
									imsi = s5_id[pkt.gtp_hdr.teid];
								}
								else
								{
									cout<<"Error: imsi not found in detach "<<pkt.gtp_hdr.teid<<endl;
									exit(-1);
								}
								pthread_mutex_unlock(&s5id_mux);

								pkt.extract_item(eps_bearer_id);
								pkt.extract_item(tai);
								
								if(gettid(imsi) != pkt.gtp_hdr.teid)
								{
									cout<<"GUTI not equal Detach"<<imsi<<" "<<pkt.gtp_hdr.teid<<endl;
									exit(-1);
								}

								pthread_mutex_lock(&uectx_mux);
								s5_cteid_ul = ue_ctx[imsi].s5_cteid_ul;
								s5_cteid_dl = ue_ctx[imsi].s5_cteid_dl;
								ue_ip_addr = ue_ctx[imsi].ip_addr;
								cout << "ul:" << s5_cteid_ul << "dl:" << s5_cteid_dl << endl;
								ue_ctx.erase(imsi);
								pthread_mutex_unlock(&uectx_mux);
								
								pthread_mutex_lock(&sgiid_mux);
								sgi_id.erase(ue_ip_addr);
								pthread_mutex_unlock(&sgiid_mux);

								pthread_mutex_lock(&s5id_mux);
								cout << "remove  data from s5 "<< imsi << " " << s5_cteid_ul << endl;
								s5_id.erase(s5_cteid_ul);
								pthread_mutex_unlock(&s5id_mux);

								pkt.clear_pkt();
								pkt.append_item(res);
								pkt.prepend_gtp_hdr(2, 4, pkt.len, s5_cteid_dl);
								
								rcvr_addr.sin_port = htons(port);
								cout << port << " " << "dl:" << s5_cteid_dl << endl;
		                        n = sendto(cafd, pkt.data, pkt.len, 0,(const struct sockaddr *)&rcvr_addr,sizeof(rcvr_addr));

		                        if(n <= 0){
		                           cout<<"Error : Write Error"<<'\n';
		                           exit(-1);
		                        } 
								
						}

						

                       // TRACE(cout << " successfully sent to SGW\n";)

                        //close(cafd);

                  }
                  

            }

         }

      }

      close(listen_fd);

   }


int main(int argc, char *argv[])
{


	//Server Socket Initialization
	listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(listen_fd < 0)
	{
		TRACE(cout<<"Error: PGW listen socket call"<<endl;)
		exit(-1);
	}
	
	int retval = make_socket_nb(listen_fd);
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp make nonblock"<<endl;)
		exit(-1);
	}

	bzero((char *) &pgw_server_addr, sizeof(pgw_server_addr));
	pgw_server_addr.sin_family = AF_INET;
	pgw_server_addr.sin_addr.s_addr = inet_addr("192.168.122.157");
	pgw_server_addr.sin_port = htons(8000);

	if (bind(listen_fd, (struct sockaddr *) &pgw_server_addr, sizeof(pgw_server_addr)) < 0) {
	      	cout<<"ERROR: BIND ERROR"<<'\n';
	      	exit(-1);      
	}


	//Initialize state here...
	s5_id.clear();
	sgi_id.clear();
	ue_ctx.clear();
	ip_addrs.clear();

	//set_ip_addrs();
	uint64_t imsi;
	int i;
	int subnet;
	int host;
	string prefix;
	string ip_addr;
	prefix = "172.16.";
	subnet = 1;
	host = 3;
	for (i = 0; i < MAX_UE_COUNT; i++) {
		imsi = 119000000000 + i;
		ip_addr = prefix + to_string(subnet) + "." + to_string(host);
		ip_addrs[imsi] = ip_addr;
		if (host == 254) {
			subnet++;
			host = 3;
		}
		else {
			host++;
		}
	}

	//Initialize locks here...
	mux_init(s5id_mux);	
	mux_init(sgiid_mux);	
	mux_init(uectx_mux);
	mux_init(listen_mux);	

	int numth = atoi(argv[1]);
	pthread_t servers[numth];
	struct thread_data arguments[numth];

	pthread_attr_t attr;
	void *status;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	//spawn server threads
	for(int i=0;i<numth;i++){
		arguments[i].core = i;		arguments[i].id = i;
		pthread_create(&servers[i],NULL,run,&arguments[i]);
	}


	//run();
	//Wait for server threads to complete
	for(int i=0;i<numth;i++){
		pthread_join(servers[i],NULL);		
	}

	//run();
	return 0;
}