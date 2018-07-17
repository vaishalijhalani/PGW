#include "K_pgw.h"

using namespace std;

#define MAX_THREADS 1

//int num_conn;
//int max_conn;

struct cadata{
   int fd,num;
};

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



void run()
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

   lsfd = socket(AF_INET, SOCK_DGRAM, 0);

   if(lsfd < 0) {
      cout<<"ERROR : opening socket"<<'\n';
         exit(-1);
      }

      make_socket_nb(lsfd);
      int uflag = 1;

   if (setsockopt(lsfd, SOL_SOCKET, SO_REUSEADDR, &uflag, sizeof(uflag)) < 0)
    {
            cout<<"Error : server setsockopt reuse"<<endl;
            exit(-2);
    }

   bzero((char *) &server, sizeof(server) );
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = inet_addr("192.168.122.157");
   server.sin_port = htons(8000);

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



   if (bind(lsfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
            cout<<"ERROR: BIND ERROR"<<'\n';
            exit(-1);      
   }

   

      int epfd = epoll_create(MAXEVENTS + 5);
      if( epfd == -1){
         cout<<"Error: epoll create"<<'\n';
         exit(-1);
      }

      int retval;
      struct epoll_event ev, rev[MAXEVENTS];

      ev.data.fd = lsfd;
      ev.events = EPOLLIN;

      retval = epoll_ctl( epfd, EPOLL_CTL_ADD, lsfd, &ev);
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

      cout<<"Entering Loop"<<'\n';
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

                        int port = ntohs(from.sin_port);

                        pkt.len = retval;
						pkt.extract_gtp_hdr();
						pkt.extract_item(s5_cteid_dl);


						if(pkt.gtp_hdr.msg_type == 1)
						{

								pkt.extract_item(imsi);
								pkt.extract_item(eps_bearer_id);
								pkt.extract_item(s5_uteid_dl);
								pkt.extract_item(apn_in_use);
								pkt.extract_item(tai);

								s5_cteid_ul = s5_cteid_dl;
								s5_uteid_ul = s5_cteid_dl;

								ue_ip_addr = ip_addrs[imsi];//locks not needed, read only

								TRACE(cout<<"3rd Attach imsi"<<imsi<<" key "<<s5_cteid_dl<<endl;)

								pthread_mutex_lock(&s5id_mux);
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
                     
                        		

		                }

		                if(pkt.gtp_hdr.msg_type == 4)
						{


								TRACE(cout <<" Detach in PGW "<< pkt.gtp_hdr.teid << endl;)
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
								ue_ctx.erase(imsi);
								pthread_mutex_unlock(&uectx_mux);
								
								pthread_mutex_lock(&sgiid_mux);
								sgi_id.erase(ue_ip_addr);
								pthread_mutex_unlock(&sgiid_mux);

								pthread_mutex_lock(&s5id_mux);
								s5_id.erase(s5_cteid_ul);
								pthread_mutex_unlock(&s5id_mux);

								pkt.clear_pkt();
								pkt.append_item(res);
								pkt.prepend_gtp_hdr(2, 4, pkt.len, s5_cteid_dl);
								//pkt.prepend_len();

								/*retval = write(cur_fd,  pkt.data, pkt.len);
								if(retval < 0)
								{
									cout<<"Error PGW write back to SGW detach"<<endl;
									exit(-1);
								}*/
								

								//fdmap.erase(cur_fd);
								
								//con_processed++;
								//TRACE(cout<<"Conn Processed "<<con_processed<<" Core "<<core<<endl;)
						}

						rcvr_addr.sin_port = htons(port);

                        n = sendto(cafd, pkt.data, pkt.len, 0,(const struct sockaddr *)&rcvr_addr,sizeof(rcvr_addr));

                        if(n <= 0){
                           cout<<"Error : Write Error"<<'\n';
                           exit(-1);
                        } 

                        TRACE(cout << " successfully sent to SGW\n";)

                        //close(cafd);

                  }
                  

            }

         }

      }

      //close(lsfd);

   }


int main()
{
   run();
   return 0;
}