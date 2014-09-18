/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*forwarding logic : obtain the routing table entry with the longest prefix matching to the input ip address */
struct sr_rt* pathSeeker(struct sr_instance* sr,uint32_t ip)
{
	assert(sr);
		
	struct sr_rt* iter = sr->routing_table;
	struct sr_rt* res = NULL;	
	uint16_t max = 0;
	uint32_t masked =0;	

	/*iterate through the routing table*/
	for (iter = sr->routing_table; iter; iter = iter->next)
	{
		/*if masked input address = masked routing table address */	
		if ((ip & iter->mask.s_addr) == (ntohl(iter->dest.s_addr) & iter->mask.s_addr))
		{
			/*network long to host long byte order*/
			masked = ntohl((iter->mask).s_addr);
			if (masked > max) /*compare with longest masked address*/
			{
				max = masked;
				res = iter;
			}
			
		}
	}
	return res;

}

/* determine whether packet is forwarded to one of the interfaces*/
int isForwardedToRouter(struct sr_instance* sr, sr_ip_hdr_t* in)
{
	struct sr_if* iter;
	for (iter = sr->if_list; iter != NULL; iter = iter->next)
	{
		if (in->ip_dst == iter->ip)
		{ return 1;}
	}
	return 0;
}

/*alternative version of handle_arpreq*/
void forwardNewRequest(struct sr_instance* sr,struct sr_arpreq* request)
{

	/*send arp request*/

	/*build an arp packet*/
        unsigned int packet_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
	uint8_t* packet_buf = (uint8_t*) malloc(packet_len);
	/*build arp packet ethernet header*/
	sr_ethernet_hdr_t* arp_ether_header = (sr_ethernet_hdr_t*) (packet_buf);
	/*build arp packet arp header*/
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet_buf+sizeof(sr_ethernet_hdr_t));
	int i;
 	for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		/*destination address is broadcast address*/
		arp_ether_header->ether_dhost[i] = 0xff;
		arp_header->ar_tha[i] = 0xff;
	}	
	/*finding source hardware / ip address of arp packet*/
	struct sr_if* iface = sr_get_interface(sr,request->interface);
	/*source hardware address*/
	memcpy(arp_ether_header->ether_shost,iface->addr,ETHER_ADDR_LEN);
	memcpy(arp_header->ar_sha,iface->addr,ETHER_ADDR_LEN);
			
	arp_ether_header->ether_type = htons(ethertype_arp); /*ARP type*/ 

	arp_header->ar_hrd = htons(arp_hrd_ethernet);
	arp_header->ar_pro = htons(ethertype_ip);
	arp_header->ar_sip = iface->ip; /*sender ip address*/
	arp_header->ar_tip = htonl(request->ip); /*arp request ip address is stored as target ip address*/
	arp_header->ar_op = htons(arp_op_request); /*operation is request*/
	arp_header->ar_hln = 6; /*length of ethernet address*/
	arp_header->ar_pln = 4; /*length of IPv4 address*/

	sr_send_packet(sr,packet_buf,packet_len,iface->name);	
	free(packet_buf); /*free unused memory*/
	return;	
}

void arpHandler(struct sr_instance* sr,uint8_t* packet, unsigned int len, struct sr_rt* best_path)
{
	/*find next hop address*/
   	uint32_t final_address = ntohl(best_path->gw.s_addr);
	/*examine ethernet header of the packet*/
	sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) packet;

	/*find next hop ip address->MAC mapping*/
	struct sr_arpentry* best_entry = sr_arpcache_lookup(&sr->cache,final_address);
	
	struct sr_if* iface = sr_get_interface(sr,best_path->interface);
	ether_header->ether_type = htons(ethertype_ip);
	memcpy(ether_header->ether_shost,iface->addr,ETHER_ADDR_LEN);
	
	if (best_entry) /*if mapping exists in cache*/
	{
		printf("mapping in cache\n");
		memcpy(ether_header->ether_dhost,best_entry->mac,ETHER_ADDR_LEN);
		sr_send_packet(sr,packet,len,best_path->interface);
		free(best_entry);
	}

	else /*otherwise insert it into cache*/
	{
		printf("insert onto cache\n");
		struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache,final_address,packet,len,best_path->interface);
		if (req->times_sent == 0)
		{
			req->interface = best_path->interface;
			forwardNewRequest(sr,req);
			req->times_sent = 1;
			req->sent = time(0);
		}

	}
	return;

}


	
/*helper function to find the name of the interface given its MAC address*/
const char* find_interface(struct sr_instance* sr,unsigned char addr[ETHER_ADDR_LEN])
{
	struct sr_if* iter = sr->if_list;
	while (iter)
	{	
		/*found the address*/
		if (memcmp(addr,iter->addr,ETHER_ADDR_LEN) == 0)
		{ return iter->name;}
		iter = iter->next;
	}	

	return 0; /*interface not found*/
}

void icmp_handler(struct sr_instance* sr,uint8_t* pkt,uint8_t type,uint8_t code)
{

	assert(sr);
	assert(pkt);
	
  	int ipLen,etherLen,icmpLen3,totalLen;
	ipLen = sizeof(sr_ip_hdr_t);
	etherLen = sizeof(sr_ethernet_hdr_t);
	icmpLen3 = sizeof(sr_icmp_t3_hdr_t);
	totalLen = ipLen+etherLen+icmpLen3;
	
	/*extract information from input packet*/
	/*sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) pkt;*/
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (pkt+etherLen); 

	struct sr_if* iter = sr->if_list;
	/*if forwarded to one of the router's interfaces*/
	while (iter)
	{
	   if (ip_header->ip_src == iter->ip)
	   {
		return;
	   }
	   iter = iter->next;
	}

	/*construct icmp reply packet*/
	unsigned int reply_pkt_len = etherLen+ipLen+icmpLen3;
	uint8_t* reply_buf = (uint8_t*)malloc(reply_pkt_len);
		
	/*construct icmp port unreachable ip header*/
	sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (reply_buf+etherLen);
	reply_ip_hdr->ip_len = htons(ipLen+icmpLen3); /*ip header + data*/
	reply_ip_hdr->ip_v = 4;
	reply_ip_hdr->ip_hl = 5;
	reply_ip_hdr->ip_ttl = 100;
	/*don't fragement. id = 0*/
	reply_ip_hdr->ip_off = htons(IP_DF);
	reply_ip_hdr->ip_id = htons(0);
	reply_ip_hdr->ip_p = ip_protocol_icmp;
	reply_ip_hdr->ip_dst = ip_header->ip_src;  
	reply_ip_hdr->ip_sum = 0;  /*initially 0*/
				
	/*construct icmp port unreachable icmp header*/
	sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*) (reply_buf+etherLen+ipLen);
	reply_icmp_hdr->icmp_type = type;
	reply_icmp_hdr->icmp_code = code;
	/*unused and mtu values are irrelevant. can be set to 0*/
	reply_icmp_hdr->unused = 0;
	reply_icmp_hdr->next_mtu = 0;
	memcpy(reply_icmp_hdr->data,pkt+etherLen,ICMP_DATA_SIZE);
	reply_icmp_hdr->icmp_sum  = 0; /*initially 0*/
	reply_icmp_hdr->icmp_sum = cksum(reply_buf+etherLen+ipLen,icmpLen3);	   
	
	/*find routing table entry with longest prefix matching to destination ip address*/
	struct sr_rt* best_path = pathSeeker(sr,ntohl(reply_ip_hdr->ip_dst));
	/*find interface corresponding to the routing table entry*/
	struct sr_if* src_iface = sr_get_interface(sr,best_path->interface);

	reply_ip_hdr->ip_src = src_iface->ip;
	reply_ip_hdr->ip_sum = cksum(reply_buf+etherLen,ipLen); /*recompute checksum*/

	arpHandler(sr,reply_buf,totalLen,best_path);
	free(reply_buf);
	return;
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/



void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
     
    /* Add initialization code here! */
    /* everything is initialized in main.c no need to implement additional init code*/	

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
 
  /*initializing key variables*/
  uint8_t* packet_buffer; /*packet buffer*/
  /*struct sr_if* iface;*/ /*interface struct*/
  uint16_t checksum,ether_type; /*checksum bit*/
  unsigned int packet_len,minlength; /*packet length*/
  int ipLen,etherLen,arpLen;
  struct sr_if* iface; 


  packet_buffer = packet;
  packet_len = len;
  minlength = sizeof(sr_ethernet_hdr_t);
  etherLen = sizeof(sr_ethernet_hdr_t); /*ethernet header size*/
  ipLen = sizeof(sr_ip_hdr_t); /*ip header length*/
  arpLen  = sizeof(sr_arp_hdr_t); /*arp header length*/

  if (len < minlength)
  {
        perror("Error: packet size too small");
	exit(1);
  }
  /*obtain interface information*/
  iface = sr_get_interface(sr,interface);
  if (!iface) /*invalid interface*/
  { 
	perror("Error: invalid Ethernet interface");
	exit(1);
  }
  
  /*examining each layer of header*/  
  
  /*examine ethernet header*/
  sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*) packet_buffer;  
  ether_type = ethertype(packet_buffer); 
 
  if (ether_type == ethertype_ip) /*IP*/
  {
	if (len < ipLen)
	{
		perror("Error: packet size too small to carry IP header");
		exit(1);
	}

	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet_buffer+etherLen);
	/*compute checksum to see if data has been corrupted*/
	uint16_t o_checksum = ip_header->ip_sum; /*original checksum*/
	checksum = cksum(packet_buffer+etherLen,ipLen);
	if (checksum != 0xffff)
	{
		/*printf("hopefully not here\n");*/
		perror("Error: data has been corrupted");
		exit(1);
	}


	else
	{	
        	ip_header->ip_sum = o_checksum; /*original checksum*/
		int isUs = isForwardedToRouter(sr,ip_header);
		if (isUs)
		{
		   /*examine protocol type*/
		   if (ip_header->ip_p == ip_protocol_icmp)
		   {
			/*examine icmp_header*/
			sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (packet_buffer+etherLen+ipLen);
		 	/*compute the checksum*/
			uint16_t icmp_checksum = icmp_header->icmp_sum;
			/*icmp checksum is computed by first zeroing out icmp_checksum field and then compute
			checksum over icmp_header and data*/
			icmp_header->icmp_sum = 0;
		 	checksum = cksum(packet_buffer+etherLen+ipLen,len-(etherLen+ipLen));
			if (checksum != icmp_checksum)
			{
				perror("Error: data has been corrupted");
				exit(1);
			}
	
		
			if (icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) /*echo request*/
			{
				
			    /*construct icmp echo reply packet*/
		  	    unsigned int reply_pkt_len = packet_len;
		            uint8_t* reply_buf = (uint8_t*)malloc(reply_pkt_len);

		  	    /*copy icmp data + icmp header*/
		            memcpy(reply_buf+etherLen+ipLen,packet_buffer+etherLen+ipLen,reply_pkt_len-etherLen-ipLen);

		 	    /*construct icmp echo reply ip header*/
		            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (reply_buf+etherLen);
		            reply_ip_hdr->ip_v = 4;
			    reply_ip_hdr->ip_hl = 5;
		            reply_ip_hdr->ip_len = htons(reply_pkt_len-etherLen); /*header + icmp header*/
		            reply_ip_hdr->ip_id = htons(0);
		            reply_ip_hdr->ip_off = htons(IP_DF);
		            reply_ip_hdr->ip_ttl = 100;
		            reply_ip_hdr->ip_p = ip_protocol_icmp;
			    /*simply swap destination and source address*/
			    reply_ip_hdr->ip_src = ip_header->ip_dst; 
			    reply_ip_hdr->ip_dst = ip_header->ip_src; 
			    reply_ip_hdr->ip_sum = 0;  /*initially 0*/
		       	    reply_ip_hdr->ip_sum = cksum(reply_buf+etherLen,ipLen); /*recompute checksum*/
		            /*construct icmp echo reply icmp header*/
				   
		            sr_icmp_hdr_t* reply_icmp_hdr = (sr_icmp_hdr_t*) (reply_buf+etherLen+ipLen);
			    reply_icmp_hdr->icmp_type = 0;
			    reply_icmp_hdr->icmp_code = 0;
			    reply_icmp_hdr->icmp_sum  = 0; /*initially 0*/
				  
			    reply_icmp_hdr->icmp_sum = cksum(reply_buf+etherLen+ipLen,reply_pkt_len-etherLen-ipLen);
				   
			    /*construct icmp echo reply ethernet header*/
	                    sr_ethernet_hdr_t* reply_ether_hdr = (sr_ethernet_hdr_t*) reply_buf;
		  	    reply_ether_hdr->ether_type = htons(ethertype_ip);	
			    memcpy(reply_ether_hdr->ether_dhost,ether_header->ether_shost,ETHER_ADDR_LEN);	
		            memcpy(reply_ether_hdr->ether_shost,ether_header->ether_dhost,ETHER_ADDR_LEN);

		            struct sr_if* witer = sr->if_list;
			    while(witer)
			    {
				if (memcmp(witer->addr,ether_header->ether_dhost,ETHER_ADDR_LEN) == 0)
				{break;}
			    }
				   
	   		    sr_send_packet(sr,reply_buf,reply_pkt_len,witer->name); 
			    free(reply_buf);
			    return;
			
			}

			else /*other ICMP messages besides ICMP echo request*/
			{
				icmp_handler(sr,packet_buffer,3,3);
				return;
			} 
	
		 }
		
		 /*if the packet contains TCP or UDP datagram*/
		 else if (ip_header->ip_p == 6 || ip_header->ip_p == 17)
		 {
		    printf("***traceroute to router interface***\n");
		    icmp_handler(sr,packet_buffer,3,3);			
		 }
	
		 else /*neither ICMP nor TCP/UDP*/
		 {	
		    return;
		 }

		}

		else /*forwarded to outer interface*/
		{
 			printf("\n\nforwarded to outer interfaces\n\n");
        		ip_header->ip_ttl--; /*decrement TTL field*/
			if (ip_header->ip_ttl == 0) /*timeout*/
			{
				/*send corresponding icmp message and drop current packet*/
				icmp_handler(sr,packet_buffer,11,0);
				return;		
			}
	
			else
			{		
		   		/*if packet has not timed out yet, recompute checksum*/
		   		ip_header->ip_sum = 0; 
		   		ip_header->ip_sum = cksum(packet_buffer+etherLen,ipLen); 

		   		/* longest prefix matching and forwarding */
		   		struct sr_rt* best_path = pathSeeker(sr,ntohl(ip_header->ip_dst));
		   		if ((best_path != NULL) && (strcmp(best_path->interface,iface->name) != 0))
		   		{
		      			arpHandler(sr,packet_buffer,len,best_path);
					return;
		   		}

		   		else
		   		{
					printf("icmp network unreachable\n");
					icmp_handler(sr,packet_buffer,3,0);
					return;
		   		}
			}
		}
	    } 
	
  }

  else if (ether_type == ethertype_arp) /*ARP*/
  {
	/*check length of packet*/
	if (len < (arpLen+etherLen))
	{	
		perror("Error: packet size too small to carry ARP message");
		exit(1);
	}
	/*extract arp header*/
	sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (packet_buffer + etherLen);


	if (arp_header->ar_hln != 6) /*ethernet address size is 6*/
	{ 
		perror("Error: invalid hardware address size");
		exit(1);
	}

	if (arp_header->ar_pln != 4) /*IPv4 address size is 4*/
	{
		perror("Error: invalid protocol address size");
		exit(1);
	}
	if ((ntohs(arp_header->ar_pro) != ethertype_ip) || (ntohs(arp_header->ar_hrd) != arp_hrd_ethernet))
	{
		perror("Error: invalid parameters");
		exit(1);
	}
	

	/*examine header type*/
	if (ntohs(arp_header->ar_op) == arp_op_request) /*received packet is an arp request*/
	{
		/*extract ethernet header from arp request*/
		sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet_buffer;
		/*extract arp header from arp request*/
		sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (packet_buffer+etherLen);
		
		/*no need to examine ethernet destination / ar_tha, since they are broadcast*/
		
		printf("***********received arp request*************\n");
		if (iface->ip == arp_hdr->ar_tip) /*this is the target interface of the arp request*/
		{
		   	/*construct arp reply packet*/
		   	unsigned int arp_packet_len = etherLen+arpLen;
		   	uint8_t* arp_packet_buff = (uint8_t*)malloc(arp_packet_len);
			/*construct ethernet header*/
			sr_ethernet_hdr_t* arp_ether_hdr_out = (sr_ethernet_hdr_t*) arp_packet_buff;
			arp_ether_hdr_out->ether_type = htons(ethertype_arp); /*ARP type, of course*/
			memcpy(arp_ether_hdr_out->ether_shost,iface->addr,ETHER_ADDR_LEN); /*source hardware adddress*/
			memcpy(arp_ether_hdr_out->ether_dhost,ether_hdr->ether_shost,ETHER_ADDR_LEN); /*destination hardware address*/
			/*construct arp header*/
			sr_arp_hdr_t* arp_hdr_out = (sr_arp_hdr_t*) (arp_packet_buff + etherLen);
			arp_hdr_out->ar_hrd = htons(arp_hrd_ethernet); /*ethernet format*/
			arp_hdr_out->ar_pro = htons(ethertype_ip); /*IPv4*/
			arp_hdr_out->ar_hln = ETHER_ADDR_LEN; /*length of ethernet address*/
			arp_hdr_out->ar_pln = 4; /*length of protocol address*/
			arp_hdr_out->ar_op  = htons(arp_op_reply); /*operation: reply*/
			arp_hdr_out->ar_sip = iface->ip; /*sender IP address*/
			memcpy(arp_hdr_out->ar_tha,arp_hdr->ar_sha,ETHER_ADDR_LEN); /*target hardware address*/
			memcpy(arp_hdr_out->ar_sha,iface->addr,ETHER_ADDR_LEN); /*sender hardware address*/
			arp_hdr_out->ar_tip = arp_hdr->ar_sip; /*target IP address*/

			/*send packet*/		
			/*print_hdrs(arp_packet_buff,arp_packet_len);*/
			sr_send_packet(sr,arp_packet_buff,arp_packet_len,iface->name);
	
		}


		return;  

	}

	else if (ntohs(arp_header->ar_op) == arp_op_reply) /*received packet is an arp reply*/
	{
		printf("*************arp_reply has been received*****************\n");		
		/*extract arp header from arp reply*/
		sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (packet_buffer+etherLen);
	  	if (arp_hdr->ar_tip == iface->ip)
		{	  
		   struct sr_arpreq* req =  sr_arpcache_insert(&sr->cache,arp_hdr->ar_sha,ntohl(arp_hdr->ar_sip));
		   if (req != NULL)
		   {
			while (req->packets != NULL)
			{
			   struct sr_packet* pkt = req->packets;
			   memcpy(((sr_ethernet_hdr_t*) pkt->buf)->ether_dhost,arp_hdr->ar_sha,ETHER_ADDR_LEN);
			   sr_send_packet(sr,pkt->buf,pkt->len,pkt->iface);
			   req->packets = req->packets->next;

			   /*free temporarily allocated memories*/
			   free(pkt->buf);
			   free(pkt->iface);	
			   free(pkt); 

			}
			/*safe to destroy request*/
			sr_arpreq_destroy(&sr->cache,req);
			
		   }
		   return;
		}
	
		else
		{ 
		   perror("doesn't have corresponding ARP request");
		   exit(1);
		}	
	}

	else /*invalid ARP type*/
	{
		perror("Error: invalid ARP type");
		exit(1);
	}

  }

  else /*invalid ethernet protocol*/ 
  {
	perror("Error: invalid ethernet message type");
	exit(1);

  }
  
}/* end sr_ForwardPacket */

