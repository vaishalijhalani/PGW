#include "mkb_mme.h"

#define MAX_THREADS 2 // This constant define number of threads available

struct arg arguments[MAX_THREADS]; // Arguments sent to Pthreads
pthread_t servers[MAX_THREADS]; // Threads 

void SignalHandler(int signum)
{
	//Handle ctrl+C here
	done = 1;
	mtcp_destroy();
	
}

//State 
uint64_t ue_count;							/* For locks couple with uectx */
unordered_map<uint32_t, uint64_t> s1mme_id; /* S1_MME UE identification table: mme_s1ap_ue_id -> guti */
unordered_map<uint64_t, UeContext> ue_ctx; /* UE context table: guti -> UeContext */


void *run(void* args)
{
	/*
		MTCP Setup
	*/

	struct arg argument = *((struct arg*)args); // Get argument 
	int core = argument.coreno; 
	mctx_t mctx ; // Get mtcp context

	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);
		
	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create
	mctx = mtcp_create_context(core);
	if (!mctx) {
		TRACE("Failed to create mtcp context!\n";)
		return NULL;
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);
	// Not reqd in MC ?

	int retval;
	map<int, mdata> fdmap;
	int i,returnval,cur_fd, act_type;
	struct mdata fddata;
	Packet pkt;
	int pkt_len;
	char * dataptr;
	unsigned char data[BUF_SIZE];
	/*
		MME Specific data
	*/
	MmeIds mme_ids;
	uint64_t imsi;
	uint64_t tai;
	uint64_t ksi_asme;
	uint16_t nw_type;
	uint16_t nw_capability;
	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t res;
	uint64_t k_asme;
	uint32_t enodeb_s1ap_ue_id;
	uint32_t mme_s1ap_ue_id;
	uint64_t guti;
	uint64_t num_autn_vectors;
	uint64_t nas_enc_algo;
	uint64_t nas_int_algo;
	uint64_t k_nas_enc;
	uint64_t k_nas_int;
	vector<uint64_t> tai_list;
	uint64_t apn_in_use;
	uint64_t k_enodeb;
	uint64_t tau_timer;
	uint32_t s11_cteid_mme;
	uint32_t s11_cteid_sgw;
	uint32_t s1_uteid_ul;
	uint32_t s1_uteid_dl;
	uint32_t s5_uteid_ul;
	uint32_t s5_uteid_dl;
	uint64_t detach_type;
	uint8_t eps_bearer_id;
	uint8_t e_rab_id;
	string pgw_s5_ip_addr;
	string ue_ip_addr;
	int tai_list_size;
	int pgw_s5_port;
	string tem;
	num_autn_vectors = 1;
	bool epsres;


	/*
		Server side initialization
	*/
	int ran_listen_fd, ran_fd;
	struct sockaddr_in mme_server_addr;
	int sgw_fd;


	ran_listen_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if(ran_listen_fd < 0)
	{
		TRACE(cout<<"Error: RAN socket call"<<endl;)
		exit(-1);
	}
	
	retval = mtcp_setsock_nonblock(mctx, ran_listen_fd);
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp make nonblock"<<endl;)
		exit(-1);
	}

	bzero((char *) &mme_server_addr, sizeof(mme_server_addr));
	mme_server_addr.sin_family = AF_INET;
	mme_server_addr.sin_addr.s_addr = inet_addr(mme_ip);
	mme_server_addr.sin_port = htons(mme_my_port);



	retval = mtcp_bind(mctx, ran_listen_fd, (struct sockaddr *) &mme_server_addr, sizeof(mme_server_addr));
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp RAN bind call"<<endl;)
		exit(-1);
	}

	retval = mtcp_listen(mctx, ran_listen_fd, MAXCONN);
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp listen"<<endl;)
		exit(-1);
	}


	/*
		Epoll Setup
	*/
	int epollfd;
	struct mtcp_epoll_event epevent;
	int numevents;
	struct mtcp_epoll_event revent;
	struct mtcp_epoll_event *return_events;
	return_events = (struct mtcp_epoll_event *) malloc (sizeof (struct mtcp_epoll_event) * MAXEVENTS);
	if (!return_events) 
	{
		TRACE(cout<<"Error: malloc failed for revents"<<endl;)
		exit(-1);
	}

	epollfd = mtcp_epoll_create(mctx, MAXEVENTS);
	if(epollfd == -1)
	{
		TRACE(cout<<"Error: mtcp mme epoll_create"<<endl;)
		exit(-1);
	}

	epevent.data.sockid = ran_listen_fd;
	epevent.events = MTCP_EPOLLIN;
	retval = mtcp_epoll_ctl(mctx, epollfd, EPOLL_CTL_ADD, ran_listen_fd, &epevent);
	if(retval == -1)
	{
		TRACE(cout<<"Error: mtcp epoll_ctl_add ran"<<endl;)
		exit(-1);
	}

	/*
	MAIN LOOP
	*/
	int con_accepts = 0;

	while(!done)
	{
		//could use done

		//watch for events
		numevents = mtcp_epoll_wait(mctx, epollfd, return_events, MAXEVENTS, -1);
		
		//epoll errors
		if(numevents < 0)
		{
			cout<<"Error: mtcp wait :"<<errno<<endl;
			if(errno != EINTR)
					cout<<"EINTR error"<<endl;
			exit(-1);
		}

		if(numevents == 0)
		{
			TRACE(cout<<"Info: Return with no events"<<endl;)
		}

		for(int i = 0; i < numevents; ++i)
		{
			//errors in file descriptors
			if( (return_events[i].events & MTCP_EPOLLERR) ||
				(return_events[i].events & MTCP_EPOLLHUP))
			{

				cout<<"\n\nError: epoll event returned : "<<return_events[i].data.sockid<<" errno :"<<errno<<endl;
				if(return_events[i].data.sockid == ran_listen_fd)
				{
					cout<<"Error: In Ran Listen fd"<<endl;
				}
				close(return_events[i].data.sockid);//mtcp
				continue;
			}

			//get an event
			revent = return_events[i];
			
			/*
				Check type of event
			*/
			if(revent.data.sockid == ran_listen_fd) 
			{	
				//If event in listening fd, its new connection
				//RAN ACCEPTS
				while(1)
				{
					ran_fd = mtcp_accept(mctx, ran_listen_fd, NULL, NULL);
					if(ran_fd < 0)
					{
						if((errno == EAGAIN) ||	(errno == EWOULDBLOCK))
						{
							break;
						}
						else
						{
							cout<<"mtcp error : error on accept "<<endl;
							exit(-1);
						}
					}
					
					epevent.events = MTCP_EPOLLIN;
					epevent.data.sockid = ran_fd;
					mtcp_setsock_nonblock(mctx, ran_fd);
					retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_fd, &epevent);
					if(retval < 0)
					{
						cout<<"Ran accept epoll add error "<<errno<<" retval "<<retval<<" core "<<core<<endl;
						exit(-1);
					}
					fddata.act = 1;
					fddata.initial_fd = -1;
					fddata.msui = -1;
					memset(fddata.buf,'\0',500);
					fddata.buflen = 0;
					fdmap.insert(make_pair(ran_fd, fddata));
					con_accepts++;
				}//while accepts
				TRACE(cout<<" Core "<<core<<" accepted "<<con_accepts<<" till now "<<endl;)
				//go to act_type case 1
			}
			else
			{
				cur_fd = revent.data.sockid;
				fddata = fdmap[cur_fd];
				act_type = fddata.act;

				//Check action type
				switch(act_type)
				{
					case 1:
						if(revent.events & MTCP_EPOLLIN)
						{
							retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
							if(retval < 0)
							{
								cout<<"Error ran epoll read delete from epoll"<<endl;
								exit(-1);
							}

							pkt.clear_pkt();
							retval = mtcp_read(mctx, cur_fd, data, BUF_SIZE);							
							if(retval == 0)
							{
								cout<<"Connection closed by RAN, handle it"<<endl;
							}
							else
							if(retval < 0)
							{
								cout<<"Error: Ran read data case 1 "<<errno<<" retval "<<retval<<" Core "<<core<<endl;
								exit(-1);
							}

							memcpy(&pkt_len, data, sizeof(int));
							dataptr = data+sizeof(int);
							memcpy(pkt.data, (dataptr), pkt_len);
							pkt.data_ptr = 0;
							pkt.len = pkt_len;

							pkt.extract_s1ap_hdr();

							if (pkt.s1ap_hdr.mme_s1ap_ue_id == 0) {
							//1st attach from ran
								num_autn_vectors = 1;
								pkt.extract_item(imsi);
								pkt.extract_item(tai);
								pkt.extract_item(ksi_asme); /* No use in this case */
								pkt.extract_item(nw_capability); /* No use in this case */
								TRACE(cout<<"A1: IMSI from RAN :"<<imsi<<" Core "<<core<<endl;)
								enodeb_s1ap_ue_id = pkt.s1ap_hdr.enodeb_s1ap_ue_id;
								guti = g_telecom.get_guti(mme_ids.gummei, imsi);

								mlock(uectx_mux);
								ue_count++;
								mme_s1ap_ue_id = ue_count;
								TRACE(cout<<"assigned:"<<guti<<":"<<ue_count<<endl;)
								ue_ctx[guti].init(imsi, enodeb_s1ap_ue_id, mme_s1ap_ue_id, tai, nw_capability);
								nw_type = ue_ctx[guti].nw_type;
								munlock(uectx_mux);

								mlock(s1mmeid_mux);
								s1mme_id[mme_s1ap_ue_id] = guti;
								munlock(s1mmeid_mux);

								//temp
								autn_num = 5;
								rand_num = 5;
								ksi_asme = 5;
								pkt.clear_pkt();
								pkt.append_item(autn_num);
								pkt.append_item(rand_num);
								pkt.append_item(ksi_asme);
							
								pkt.prepend_s1ap_hdr(1, pkt.len, enodeb_s1ap_ue_id, mme_s1ap_ue_id);
								pkt.prepend_len();

								retval = mtcp_write(mctx, cur_fd, pkt.data, pkt.len);
								if(retval < 0)
								{
									cout<<"Error send pkt to RAN"<<endl;
									exit(-1);	
								}
								fdmap.erase(cur_fd);
								mtcp_close(mctx, cur_fd);
							}//1st attach ends
							else
							{
								cout<<"Error ran pkt Wrong Header "<<endl;
								exit(-1);
							}

						}// case 1 right event
						else
						{
							cout<<"Error: Wrong event in act case 1"<<endl;
							exit(-1);
						}//case 1 wrong event
					break;//case 1
	
					default:
						cout<<"Error unknown switch case"<<endl;
					break;//default
				}//switch close;
			}//close for action events
		}//for i-numevents loop ends
	}//end while(1);
}//end run()


int main()
{

	char* conf_file = "server.conf";
	int ret;
 
     /* initialize mtcp */
	if(conf_file == NULL)
	{
		cout<<"Forgot to pass the mTCP startup config file!\n";
		exit(EXIT_FAILURE);
	}
	else
	{
		TRACE_INFO("Reading configuration from %s\n",conf_file);
	}

	//step 1. mtcp_init, mtcp_register_signal(optional)
	ret = mtcp_init(conf_file);
	if (ret) {
		cout<<"Failed to initialize mtcp\n";
		exit(EXIT_FAILURE);
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	//Initialize locks, used for multicore
	s1mme_id.clear();
	ue_ctx.clear();
	ue_count = 0;
	done = 0;

	mux_init(s1mmeid_mux);
	mux_init(uectx_mux);



	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		pthread_create(&servers[i],NULL,run,&arguments[i]);
	}


	//run();
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(servers[i],NULL);		
	}

	//run();
	return 0;
}