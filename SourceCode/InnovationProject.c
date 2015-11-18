/* This program is made to demonstrate 
 * How to process packets using OnePK app
 * The program is written and based on DatapathTutorial program
 * provided by Cisco in their onePK SDK.
 *
 * The program uses SessionElement program to establish connection
 *
 * Written by Maksim Sisov
 */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "onep_core_services.h"
#include "onep_policy_bulk.h"
#include "onep_datapath_policy.h"
#include "onep_class.h"
#include "onep_filter.h"
#include "onep_dpss_packet_delivery.h"
#include "onep_types.h"
#include "onep_dpss_actions.h"
#include "onep_dpss_pkt.h"
#include "onep_dpss_flow.h"
#include "onep_dpss_callback_framework.h"

#include "session_element_util.h"
#include "include/datapath_util.h"
#define FAIL false
#define SUCCESS true
#define DPSS_ACTION_MAX_LEN (20)

static onep_network_element_t*  ne = NULL;
onep_policy_global_cap_t *global_cap = NULL;
onep_policy_cap_filter_t *filter_cap = NULL;
onep_collection_t *tables = NULL;
onep_collection_t*  intfs = NULL;
onep_network_interface_t* intf;

//global argc and argv[]
char **gargv;
int gargc;

int brake_value = 0; //value for stopping or executing thread
int drop_rate = 100; //100 - 100 = 0% drop rate
int m_packet = 1; //1-100 packet counter
long int count = 1; //overall packets counter

struct timespec t_received; //packets received time
struct timespec t_received_prev; //prev received time
struct timespec t_received_result;
struct timespec t_sum; //sum of time between received packets 
//shortest received time
int min_sec;
long min_nanosec;
//longest received time
int max_sec;
long max_nanosec;	

int fd_dropped;
int fd_count;

FILE *saved_stdout;

static int proto;

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/*
 * Extract the IP version from a packet.
 */
onep_status_t get_ip_version(struct onep_dpss_paktype_ *pakp,
    char *ip_version) {

    onep_status_t rc;
    uint16_t l3_protocol;
    char l3_prot_sym = 'U';

    /* Get packet L3 protocol. */
    rc = onep_dpss_pkt_get_l3_protocol(pakp, &l3_protocol);
    if( rc == ONEP_OK ) {
        if( l3_protocol == ONEP_DPSS_L3_IPV4 ) {
            l3_prot_sym = '4';
        } else if( l3_protocol == ONEP_DPSS_L3_IPV6 ) {
            l3_prot_sym = '6';
        } else if( l3_protocol == ONEP_DPSS_L3_OTHER ) {
            l3_prot_sym = 'N';
        } else {
            l3_prot_sym = 'U';
        }
    } else {
        fprintf(stderr, "Error getting L3 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }
    *ip_version = l3_prot_sym;
    return (ONEP_OK);
}


/*
 * Extract IP addressing and port information from the packet.
 */
onep_status_t get_ip_port_info(
    struct onep_dpss_paktype_ *pakp, char **src_ip, char **dest_ip,
    uint16_t *src_port, uint16_t *dest_port, char *prot, char ip_version ) {

    onep_status_t   rc;
    uint8_t         l4_protocol;
    uint8_t         *l3_start;
    struct iphdr    *l3hdr;
    uint8_t         *l4_start;
    struct tcphdr   *l4tcp;
    struct udphdr   *l4udp;

    if( ip_version == '4' ) {
        /* get IPv4 header */
        rc = onep_dpss_pkt_get_l3_start(pakp, &l3_start);
        if( rc==ONEP_OK ) {
            l3hdr = (struct iphdr *)l3_start; // convert to iphdr
            *src_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->saddr) ));
            *dest_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->daddr) ));
        } else {
            fprintf(stderr,"Error getting IPv4 header. code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
            return (ONEP_ERR_SYSTEM);
        }
    } else if( ip_version == '6' ) {
        fprintf(stderr, "Cannot get IPv6 traffic at this time.\n");
        return (ONEP_ERR_SYSTEM);
    } else if( ip_version == 'N' ) {
        fprintf(stderr, "IP address is neither IPv4 nor IPv6.\n");
        return (ONEP_ERR_SYSTEM);
    } else {
        fprintf(stderr, "Unknown IP version.\n");
        return (ONEP_ERR_SYSTEM);
    }

    /* get L4 header */
    rc = onep_dpss_pkt_get_l4_start(pakp, &l4_start);
    if( rc != ONEP_OK ) {
        fprintf(stderr, "Error getting L4 header. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }

    /* get packet L4 protocol */
    rc = onep_dpss_pkt_get_l4_protocol(pakp, &l4_protocol);
    if( rc == ONEP_OK ) {
        if( l4_protocol == ONEP_DPSS_TCP_PROT ) {
            /* TCP */
            strcpy(prot,"TCP");
            l4tcp = (struct tcphdr *)l4_start;
            *src_port = ntohs( l4tcp->source );
            *dest_port = ntohs( l4tcp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_UDP_PROT ) {
            /* UDP */
            strcpy(prot,"UDP");
            l4udp = (struct udphdr *)l4_start;
            *src_port = ntohs( l4udp->source );
            *dest_port = ntohs( l4udp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_ICMP_PROT ) {
            strcpy(prot,"ICMP");
        }
        else if( l4_protocol == ONEP_DPSS_IPV6_ENCAPSULATION_PROT ) {
            // sends IPV6 packet as payload of IPV4
            strcpy(prot,"ENCP"); // IPV6 encapsulated on IPV4
        }
        else {
            strcpy(prot,"UNK!"); // Unknown!
        }
    }
    else {
        fprintf(stderr, "Error getting L4 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return (ONEP_OK);
}


/*
 * Extract some flow state given a packet and a FID.
 */
void get_flow_state(struct onep_dpss_paktype_ *pakp,
    onep_dpss_flow_ptr_t fid, char *l4_state_char ) {

    onep_status_t             rc;
    onep_dpss_l4_flow_state_e l4_state;

    rc = onep_dpss_flow_get_l4_flow_state(pakp,&l4_state);
    if( rc==ONEP_OK ) {
        if( l4_state == ONEP_DPSS_L4_CLOSED ) {
            strcpy(l4_state_char,"CLOSED");
        } else if( l4_state == ONEP_DPSS_L4_OPENING ) {
            strcpy(l4_state_char,"OPENING");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED ) {
            strcpy(l4_state_char,"BI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"BI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_CLOSING ) {
            strcpy(l4_state_char,"CLOSING");
        } else {
            strcpy(l4_state_char,"!UNKNOWN!");
        }
    } else {
        fprintf(stderr, "Error getting L4 state of flow. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return;
}

/*
 * Packet callback that shows packet information
 * And drops packets according to packet drop rate.
 */
void display_pak_info_callback(onep_dpss_traffic_reg_t *reg,
    struct onep_dpss_paktype_ *pak, void *client_context, bool *return_packet) {
	
	static int dropped_packets = 0; // dropped packet counter

    	onep_status_t        rc;
    	onep_dpss_fid_t      fid;
    	char                 ipv = 0;
    	uint16_t             src_port = 0;
    	uint16_t             dest_port = 0;
    	char                 *src_ip = NULL;
    	char                 *dest_ip = NULL;
    	char                 l4_protocol[5];
  	char                 l4_state[30];

	int backup_time;
	long backup_nanotime;
	int time_calculated;
	long nanotime_calculated;
	char buff[20];

    	strcpy(l4_protocol,"ERR");
   	strcpy(l4_state,"ERR");

    	rc = onep_dpss_pkt_get_flow(pak, &fid);
    	if( rc == ONEP_OK ) {

	//count time
	if(count == 1){
		//get time for the first time packet received. this is a starting point for counting
		if((clock_gettime(CLOCK_MONOTONIC, &t_received)) == -1){
			perror("clock_gettime");	
		}
	}
	else if (count > 1){	
		//get time for new packets
		t_received_prev.tv_sec = t_received.tv_sec;
		t_received_prev.tv_nsec = t_received.tv_nsec;
		if((clock_gettime(CLOCK_MONOTONIC, &t_received)) == -1){
			perror("clock_gettime");	
		}
		else {

			timespec_diff(&t_received_prev, &t_received, &t_received_result);

			t_sum.tv_sec = t_sum.tv_sec + t_received_result.tv_sec; //in sec
			t_sum.tv_nsec = t_sum.tv_nsec + t_received_result.tv_nsec; //in nano sec

			if(count == 2){ //start comparing min and max time only after we got first full information about times
				min_sec = t_received_result.tv_sec;
				max_sec = t_received_result.tv_sec;
				min_nanosec = t_received_result.tv_nsec;
				max_nanosec = t_received_result.tv_nsec;
			}	
			else if (count > 2){
				//get minimum
				if(min_sec > t_received_result.tv_sec){
					min_sec = t_received_result.tv_sec;
					min_nanosec = t_received_result.tv_nsec;
				}
				else if (min_sec == t_received_result.tv_sec){
					if(min_nanosec > t_received_result.tv_nsec){
						min_nanosec = t_received_result.tv_nsec;				
					}
				}
				//get maximum
				if(max_sec < t_received_result.tv_sec){
					max_sec = t_received_result.tv_sec;
					max_nanosec = t_received_result.tv_nsec;
				}
				else if (max_sec == t_received_result.tv_sec){
					if(max_nanosec < t_received_result.tv_nsec){
						max_nanosec = t_received_result.tv_nsec;				
					}
				}
			}
		}	
	}	

        rc = get_ip_version(pak, &ipv);
        if( rc != ONEP_OK ) {
            fprintf(stderr, "Error in get ip version: code[%d], text[%s]\n",
                    rc, onep_strerror(rc));
        }
        rc = get_ip_port_info(pak, &src_ip,
                                            &dest_ip,
                                            &src_port,
                                            &dest_port,
                                            l4_protocol,
                                            ipv);
        if( rc != ONEP_OK ) {
          fprintf(stderr, "Error in get ip port info: code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
        }
        get_flow_state(pak, fid, l4_state);

    	} else {
        fprintf(stderr, "Error getting flow ID. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    	}
    
	if(m_packet > drop_rate){
		rc = onep_dpss_drop_packet(pak);
		printf(
			"\n"
			"\033[22;4;30m"
			"| FID | IPv | Source                  |"
			" Destination           | Prot |Dropped#| State                              |\n"
			"\033[0m");
	    	printf(
			"| %-3"PRIu64" |  %c  | %-15s : %-5d | %-15s : %-5d | %-4s | %3d  | %-25s - dropped|\n\n",
			fid, ipv, src_ip, src_port, dest_ip, dest_port,
			l4_protocol, ++dropped_packets, l4_state, "- dropped");
		//print the same information to file
		stdout = fopen("dropped_packets_log.txt", "a");
		printf(
			"\n"
			"| FID | IPv | Source                  |"
			" Destination             | Prot | Pkt# | State                              |\n");
		printf(
		      "| %-3"PRIu64" |  %c  | %-15s : %-5d | %-15s : %-5d | %-4s | %3d  | %-25s - dropped|\n\n",
		      fid, ipv, src_ip, src_port, dest_ip, dest_port,
		      l4_protocol,count, l4_state);
		fclose(stdout);
		stdout = saved_stdout;
	}
	else {
		printf(
			"\n"
			"\033[22;4;30m"
			"| FID | IPv | Source                  |"
			" Destination           | Prot | Pkt# | State                     |\n"
			"\033[0m");
		printf(
		      "| %-3"PRIu64" |  %c  | %-15s : %-5d | %-15s : %-5d | %-4s | %3d  | %-25s |\n\n",
		      fid, ipv, src_ip, src_port, dest_ip, dest_port,
		      l4_protocol,count, l4_state);
	}
	
	if(m_packet >= 100){
			m_packet = 1;		
	}	

    	count++;
    	m_packet++;
    	free(src_ip);
    	free(dest_ip);
    	return;
}

void get_interface_filter(onep_interface_filter_t* intf_filter){
	int count = 0;
	onep_status_t rc;
	onep_interface_filter_t* my_filter = NULL;
     /*
      * Get list of interfaces on device, then find the interface we want.
      */
     rc = onep_interface_filter_new(&my_filter);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError creating intf filter. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
     }
     rc = onep_element_get_interface_list(ne, my_filter, &intfs);
     if (rc != ONEP_OK) {
        fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                rc, onep_strerror(rc));
     }
     rc = onep_collection_get_size(intfs, &count);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
     }
     if (count <= 0 ) {
        fprintf(stderr, "\nNo interfaces available");
     }
     intf_filter = my_filter;
}

/*
 * Calculate time difference
 */
void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    result->tv_sec = 0;
    result->tv_nsec = 0;
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
 
    return;
}

/*
 * Display a list of interfaces.
 */
int display_intf_list(FILE *op, int get_name, int intfs_num, onep_if_name* func_name)
{
    onep_status_t rc;
    unsigned int count;
    onep_if_name name;

    onep_interface_filter_t* intf_filter = NULL;
    get_interface_filter(intf_filter);
    if(get_name == 1){
	    rc = onep_collection_get_by_index(intfs, intfs_num, (void *)&intf);
	    if (rc==ONEP_OK) {
		rc = onep_interface_get_name(intf,func_name);
		fprintf(op, "[%d] Interface [%s]\n", intfs_num, func_name);
	    } else {
 	        fprintf(stderr, "Error getting interface. code[%d], text[%s]\n",
		rc, onep_strerror(rc));
	}
    }
    else {
    	onep_collection_get_size(intfs, &count);
	    if (count>0) {
		unsigned int i;
		for (i = 0; i < count; i++) {
		    rc = onep_collection_get_by_index(intfs, i, (void *)&intf);
		    if (rc==ONEP_OK) {
		        rc = onep_interface_get_name(intf,name);
		        fprintf(op, "[%d] Interface [%s]\n", i, name);
		    } else {
		       fprintf(stderr, "Error getting interface. code[%d], text[%s]\n",
		       rc, onep_strerror(rc));
		    }
		}
	    }
	}
	return count;
}

/*
 *   Get traffic action table
 */
onep_status_t find_datapath_table(
    onep_network_element_t *elem,
    onep_policy_table_cap_t **table_cap)
{
    onep_status_t rc = ONEP_OK;
    uint32_t table_count = 0;
    onep_collection_t  *matches = NULL, *actions = NULL;
    onep_iterator_t *table_iter, *match_iter, *action_iter;
    bool found = false;
    onep_policy_table_cap_t *table;
    onep_policy_global_cap_t *global_cap;
    onep_policy_cap_filter_t *filter_cap;
    onep_policy_match_cap_t *match_cap;
    onep_policy_match_type_e match_type;
    onep_policy_action_cap_t *action_cap;
    onep_policy_action_type_e action_type;
    onep_status_t destroy_rc = ONEP_OK;

    /* Get traffic action table */
    rc = onep_policy_get_global_capabilities(elem, &global_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in get global cap: %s\n\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_cap_filter_new(&filter_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in cap filter: %s\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_global_cap_get_table_list(global_cap, filter_cap, &tables);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting table list: %s\n", onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_collection_get_size(tables, &table_count);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get cap table size : %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

    /*
     * Need to have >0 datapath tables
     */
    if (table_count==0) {
      printf("table count = 0\n");
      return ONEP_FAIL;
    }

    rc = onep_collection_get_iterator(tables, &table_iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

    rc = onep_policy_cap_filter_set_supported(filter_cap);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in set filter supported: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }
    
    /* Query all tables to determine table that supports Datapath actions and ACL matches*/
    while ((table = (onep_policy_table_cap_t *)onep_iterator_next(table_iter)) && !found) {
        rc = onep_policy_table_cap_get_match_list(table, filter_cap, &matches);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in get match list: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        rc = onep_collection_get_iterator(matches, &match_iter);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        while ((match_cap = (onep_policy_match_cap_t *)onep_iterator_next(match_iter)) && !found) {
            rc = onep_policy_match_cap_get_type(match_cap, &match_type);
            if(rc != ONEP_OK) {
              fprintf(stderr, "\nError in get match type: %d, %s\n",
                    rc, onep_strerror(rc));
              goto cleanup;
            }

            if(match_type == ONEP_POLICY_MATCH_TYPE_ACL) {
                rc = onep_policy_table_cap_get_action_list(table, filter_cap, &actions);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in get match list: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }
                rc = onep_collection_get_iterator(actions, &action_iter);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in get cap table iterator: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }

                while ((action_cap = (onep_policy_action_cap_t *)onep_iterator_next(action_iter)) && !found) {
                    rc = onep_policy_action_cap_get_type(action_cap, &action_type);
                    if(rc != ONEP_OK) {
                      fprintf(stderr, "\nError in get match type: %d, %s\n",
                            rc, onep_strerror(rc));
                      goto cleanup;
                    }

                    if(action_type == ONEP_POLICY_ACTION_TYPE_COPY) {
                        *table_cap = table;
                        found = true;
                    }
                }
                rc = onep_collection_destroy(&actions);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in destroy collection: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }

                rc =  onep_iterator_destroy(&action_iter);
                if(rc != ONEP_OK) {
                  fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
                        rc, onep_strerror(rc));
                  goto cleanup;
                }
            }
        }
        rc = onep_collection_destroy(&matches);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in destroy collection: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        rc =  onep_iterator_destroy(&match_iter);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    }

    rc =  onep_iterator_destroy(&table_iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in destroy iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }
    
    return rc;
    
    cleanup:
        
        if(matches){
    	    destroy_rc = onep_collection_destroy(&matches);
    	    if(destroy_rc != ONEP_OK) {
    				 fprintf(stderr, "\nError in destroy matches : %d, %s",
    						destroy_rc, onep_strerror(destroy_rc));
    	    }
    	}
    
	if(actions){
		destroy_rc = onep_collection_destroy(&actions);
		if(destroy_rc != ONEP_OK) {
				 fprintf(stderr, "\nError in destroy actions : %d, %s",
						destroy_rc, onep_strerror(destroy_rc));
		 }
	}
		
	if(table_iter){
		destroy_rc = onep_iterator_destroy(&table_iter);
		if(destroy_rc != ONEP_OK) {
					fprintf(stderr, "\nError in destroy table_iter : %d, %s",
									destroy_rc, onep_strerror(destroy_rc));
                }
	 }
		
	if(match_iter){
            destroy_rc = onep_iterator_destroy(&match_iter);
            if(destroy_rc != ONEP_OK) {
					fprintf(stderr, "\nError in destroy match_iter : %d, %s",
							destroy_rc, onep_strerror(destroy_rc));
        	}
			}
		
	if(action_iter){
        	destroy_rc = onep_iterator_destroy(&action_iter);
		if(destroy_rc != ONEP_OK) {
	 				fprintf(stderr, "\nError in destroy action_iter : %d, %s",
	 						destroy_rc, onep_strerror(destroy_rc));
	        }
         }
		
    return rc;
}

/*
 * Example function to create a simple ACL and Policy Map
 */
onep_status_t create_ip_pmap (
    onep_network_element_t *elem,
    onep_dpss_pak_callback_t callback,
    onep_dpss_pkt_action_type_e action,
    onep_policy_pmap_handle_t *pmap_handle,
    onep_policy_pmap_op_t *pmap_op,
    onep_policy_op_list_t *pmap_op_list,
    onep_policy_op_list_t *cmap_op_list,
    onep_policy_cmap_handle_t *cmap_handle,
    onep_policy_cmap_op_t *cmap_op,
    onep_acl_t ** acl)
{
    onep_ace_t *ace40 = 0;
    onep_acl_t *onep_acl = 0;
    onep_collection_t *result_list = 0;
    onep_iterator_t *iter = 0;
    onep_policy_action_holder_t *ah = 0;
    onep_policy_action_t *dp_action = 0;
    onep_policy_entry_op_t *entry_op;
    onep_policy_match_holder_t *mh = 0;
    onep_policy_match_t *match = 0;
    onep_policy_table_cap_t *table_cap = 0;
    onep_status_t rc = ONEP_OK;
    onep_status_t destroy_rc = ONEP_OK;

    /* create a simple ACL, ip any any */
    rc = onep_acl_create_l3_acl(AF_INET, elem, &onep_acl);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_create_l3_acl: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Create ACE40(seq=40, permit)
    rc = onep_acl_create_l3_ace(40, TRUE, &ace40);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_create_l3_ace: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 src prefix
    rc = onep_acl_set_l3_ace_src_prefix(ace40, NULL, 0);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_prefix : %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest prefix
    rc = onep_acl_set_l3_ace_dst_prefix(ace40, NULL, 0);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_prefix: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest port
    rc = onep_acl_set_l3_ace_protocol(ace40, proto);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_protocol: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 src port
    rc = onep_acl_set_l3_ace_src_port(ace40, 0, ONEP_COMPARE_ANY);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_port: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest port
    rc = onep_acl_set_l3_ace_dst_port(ace40, 0, ONEP_COMPARE_ANY);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_port: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Add ACE40 to ACL
   rc = onep_acl_add_ace(onep_acl, ace40);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_add_ace: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   /*
    * Get traffic action table
    */
    rc = find_datapath_table(elem, &table_cap);
    if(rc != ONEP_OK) {
      goto cleanup;
    }
    

    /*
     * Create a policy using the class just created.
     */

    /* 1. Create the op_list */
    rc = onep_policy_pmap_op_list_new(&pmap_op_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_list_new: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 2. Add the network element */
    rc = onep_policy_op_add_network_element(pmap_op_list, elem);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 3. Add pmap create operation to list */
    rc = onep_policy_pmap_op_create(pmap_op_list, table_cap, &pmap_op);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_create: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 4. Add an entry */
    if(onep_policy_table_cap_supports_sequence_insertion(table_cap)){ 
        rc = onep_policy_pmap_op_entry_insert_sequence(pmap_op, 200, &entry_op);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_pmap_op_entry_insert_sequence: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    } else {
        rc = onep_policy_pmap_op_entry_insert_end(pmap_op, &entry_op);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_pmap_op_entry_insert_end: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    }

    if (onep_policy_table_cap_supports_persistent(table_cap)) {
        rc =  onep_policy_pmap_op_set_persistent(pmap_op, "onep-dp-tutorial-pmap");
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_pmap_op_set_persistent: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    } else {
        rc =  onep_policy_pmap_op_set_transient(pmap_op);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_pmap_op_set_transient: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    }

    if (onep_policy_table_cap_supports_cmap(table_cap)) {
        /*
         * Create a class based on the ACL.
         */

        /* 1. Create the op_list */
        rc = onep_policy_cmap_op_list_new(&cmap_op_list);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_cmap_op_list_new: %d, %s\n",
                   rc, onep_strerror(rc));
          goto cleanup;
        }

        /* 2. Add the network element */
        rc = onep_policy_op_add_network_element(cmap_op_list, elem);
        if(rc != ONEP_OK) {
             fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
                   rc, onep_strerror(rc));
             goto cleanup;
        }

        /* 3. Create a specific operation on the list */
        rc = onep_policy_cmap_op_create(cmap_op_list, table_cap, &cmap_op);
        if(rc != ONEP_OK) {
             fprintf(stderr, "\nError in onep_policy_cmap_op_create: %d, %s\n",
                   rc, onep_strerror(rc));
             goto cleanup;
        }

        if (onep_policy_table_cap_supports_persistent(table_cap)) {
            rc =  onep_policy_cmap_op_set_persistent(cmap_op, "onep-dp-tutorial-cmap");
            if(rc != ONEP_OK) {
              fprintf(stderr, "\nError in onep_policy_cmap_op_set_persistent: %d, %s\n",
                    rc, onep_strerror(rc));
              goto cleanup;
            }
        } 

        /* 4. Get the match holder for the operation instance */
        rc = onep_policy_cmap_op_get_match_holder(cmap_op, &mh);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_cmap_op_get_match_holder: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        /* 5. Add an access list match */
        rc = onep_policy_match_add_access_list( mh, (onep_policy_access_list_t *)onep_acl, &match);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_match_add_access_list: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        /* 6. Submit the operation. */
        rc = onep_policy_op_update(cmap_op_list);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_op_update 1: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }

        /* 7. Find the cmap_handle we just created */
        rc = onep_policy_op_list_get_list(cmap_op_list, &result_list);
        if(rc != ONEP_OK) {
             fprintf(stderr, "\nError in onep_policy_op_list_get_list: %d, %s\n",
                   rc, onep_strerror(rc));
             goto cleanup;
        }

        rc = onep_collection_get_iterator(result_list, &iter);
        if(rc != ONEP_OK) {
             fprintf(stderr, "\nError in onep_collection_get_iterator: %d, %s\n",
                   rc, onep_strerror(rc));
             goto cleanup;
        }
        
        cmap_op = (onep_policy_cmap_op_t *)onep_iterator_next(iter);
            if (!cmap_op) {
              fprintf(stderr, "\nError in getting policy op\n");
              goto cleanup;
         }

         rc = onep_policy_cmap_op_get_handle(cmap_op, cmap_handle);
            if(rc != ONEP_OK) {
              fprintf(stderr, "\nError in creating class map : %d, %s\n",
                    rc, onep_strerror(rc));
              goto cleanup;
        }


        /* 5. Set the cmap on the entry */
        rc = onep_policy_entry_op_add_cmap(entry_op, *cmap_handle);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_entry_op_add_cmap: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    } else {
        rc = onep_policy_entry_op_get_match_holder(entry_op, &mh);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_entry_op_get_match_holder: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
        /* 5. Add an access list match */
        rc = onep_policy_match_add_access_list( mh, (onep_policy_access_list_t *)onep_acl, &match);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_match_add_access_list: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
        }
    }

    /* 6. Try and add an action */
    rc = onep_policy_entry_op_get_action_holder(entry_op, &ah);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_entry_op_get_action_holder: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    if (action==ONEP_DPSS_ACTION_COPY) {
      //printf ("Adding ONEP DPSS Action Copy\n");
      rc = onep_policy_action_add_copy(ah, callback, NULL, &dp_action);
      if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_action_add_copy: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
      }
    }

    else if (action==ONEP_DPSS_ACTION_DIVERT || action==ONEP_DPSS_ACTION_PUNT){
	//printf("adding action divert and punt\n");
	rc = onep_policy_action_add_divert(ah, callback, NULL, &dp_action);
	if(rc != ONEP_OK){
		fprintf(stderr, "\nError in onep_policy_action_add_divert: %d, %s", rc, onep_strerror(rc));
	goto cleanup;	
	}
	if(action==ONEP_DPSS_ACTION_PUNT){
		rc = onep_policy_action_set_stateful(dp_action);
		if(rc != ONEP_OK){
			printf(stderr, "\nError in setting action to stateful: %d, %s", rc, onep_strerror(rc));
		}
	}
	
    }	

    /* 7. Submit the operation. */
    rc = onep_policy_op_update(pmap_op_list);
   
    if(rc != ONEP_OK) {
       fprintf(stderr, "\nError in onep_policy_op_update: %d, %s\n",
             rc, onep_strerror(rc));
       goto cleanup;
    }

    /* 8. Find the pmap_handle we just created */
    rc = onep_policy_op_list_get_list(pmap_op_list, &result_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_list_get_list: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    rc = onep_collection_get_iterator(result_list, &iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_collection_get_iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }
    
   
    pmap_op = (onep_policy_pmap_op_t *)onep_iterator_next(iter);
        if (!pmap_op) {
          fprintf(stderr, "Error in getting pmap_op\n");
          rc = ONEP_FAIL;
          goto cleanup;
         }

    rc = onep_policy_pmap_op_get_handle(pmap_op, pmap_handle);
        if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in onep_policy_pmap_op_get_handle: %d, %s\n",
                rc, onep_strerror(rc));
          goto cleanup;
    }


   /* Return the acl we created */
   *acl = onep_acl;
   
   cleanup:
   
   if(cmap_op_list) {
	   destroy_rc = onep_policy_op_list_destroy(&cmap_op_list);
	   if(destroy_rc != ONEP_OK) {
		 fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
			 destroy_rc, onep_strerror(destroy_rc));
	   }
    }
   if(pmap_op_list) {
	   destroy_rc = onep_policy_op_list_destroy(&pmap_op_list);
	   if(destroy_rc != ONEP_OK) {
	       fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
		       destroy_rc, onep_strerror(destroy_rc));
	    }
   }
   return rc;
}

void *thread_program_run(void *p){
   onep_session_handle_t* sh;
   uint64_t pak_count, last_pak_count = 0;
   int timeout = 1;
   int loop_count = 1;
   unsigned int count = 0;
   onep_status_t       rc;
   onep_status_t destroy_rc;
   uint64_t mean = 0;
   long nanomean = 0;
   long int c_count = 0;

   onep_interface_filter_t* intf_filter = NULL;
  // onep_collection_t*  intfs = NULL;
   onep_policy_op_list_t *cmap_op_list = NULL;
   onep_policy_op_list_t *pmap_op_list = NULL;
   onep_policy_pmap_handle_t pmap_handle = 0;
   onep_policy_pmap_op_t *pmap_op = NULL;
   onep_policy_op_list_t *target_op_list = NULL;
   onep_policy_cmap_handle_t cmap_handle;
   onep_policy_cmap_op_t *cmap_op = NULL;
   onep_policy_target_op_t *target_op = NULL;
   onep_dpss_pkt_action_type_e the_action;
   onep_acl_t * acl = NULL;
   onep_dpss_pak_callback_t the_callback_handler;


	//initialize time structure to zero
	t_received.tv_sec = 0;
	t_received.tv_nsec = 0;
	t_sum.tv_sec = 0;
	t_sum.tv_nsec = 0;

     //get interfaces
     get_interface_filter(intf_filter);

    /*
     * Display the interfaces we retrieved
     */
    display_intf_list(stderr, 0, 0, NULL);

    /*
     * Register some packet handlers.
     */
   onep_network_interface_t *intf;
   printf("\nName of interface expecting packets: %s\n", *(onep_if_name *)p);
   rc = onep_element_get_interface_by_name(ne, *(onep_if_name *)p, &intf);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting interface: %s\n", onep_strerror(rc));
      goto cleanup;
   }

  /*
   * Policy action punt - redirect packet to DPSS and program will decide whether forward or not.
   */

   the_action = ONEP_DPSS_ACTION_PUNT;
   /* Callback function for processing packets.*/
   the_callback_handler = display_pak_info_callback;

   /* create a simple ACL and onep Policy map */
   rc = create_ip_pmap(ne,
          the_callback_handler,
          the_action,
          &pmap_handle, 
          pmap_op,
          pmap_op_list,
          cmap_op_list,
          &cmap_handle,
          cmap_op,
          &acl);
   if(rc != ONEP_OK) {
      goto cleanup;
   }
   //Register for packets
   /*
    * Activate policy on interface
    *
    * So, first create a target operation list and set the network
    * element on it.
    */
   rc = onep_policy_target_op_list_new(&target_op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_list_new: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_op_add_network_element(target_op_list, ne);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   /* Add request to bind policy to interface */
   rc = onep_policy_target_op_activate(target_op_list, &target_op);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_activate: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_add_pmap(target_op, pmap_handle);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_pmap: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_add_interface(target_op, intf);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_interface: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   
   //End register_packets

   rc = onep_policy_op_update(target_op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_update: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   printf ("Finished applying policy on interface\n");

   pthread_mutex_lock(&mut);
   pthread_cond_signal(&cond);
   pthread_mutex_unlock(&mut);

   last_pak_count = 0;
   /* wait in packet loop
    * if menu buttons pressed, exit
    */
   printf ("\n\nWaiting for packets...Current drop rate is %d%\n", (100 - drop_rate));
   while(1){
     //sleep(timeout);
	nanosleep(400000000, NULL);
      if(brake_value == 1){
		write(STDOUT_FILENO, "Stopping the program\n", 21);	
		break;
	}
   }


  printf("\n\n******* DISCONNECT AND CLEAN UP *******\n\n");

   /*Remove the policies applied to network element */
   
   if(target_op_list) {
           rc = onep_policy_op_list_destroy(&target_op_list);
           if (ONEP_OK != rc) {
                fprintf(stderr, "\nError in destroying target op list : %d, %s", rc, onep_strerror(rc));
                goto cleanup;
           }
    }

    rc = onep_policy_target_op_list_new(&target_op_list);
       if(rc != ONEP_OK) {
            fprintf(stderr, "\nError in creating target op list : %d, %s", rc, onep_strerror(rc));
            goto cleanup;
    }
       
    //deactivate target
    rc = onep_policy_target_op_deactivate(target_op_list, &target_op);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in deactivating target op : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }
      
    rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);
    if(rc != ONEP_OK) {
           fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
                 rc, onep_strerror(rc));
           goto cleanup;
    }

    //add interface group to the target
    rc = onep_policy_target_op_add_interface(target_op, intf);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in adding interface to target : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }

    rc = onep_policy_target_op_add_pmap(target_op, pmap_handle);
    if(rc != ONEP_OK) {
          fprintf(stderr, "\nError in adding pmap handle to target : %d, %s", rc, onep_strerror(rc));
          goto cleanup;
    }

    rc = onep_policy_op_add_network_element(target_op_list, ne);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in sending target op list to network element : %d, %s", rc, onep_strerror(rc));
         
    }

    rc = onep_policy_op_update(target_op_list);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in updating target op list : %d, %s", rc, onep_strerror(rc));
         
    }
	 // removing policy map
	 if(pmap_op_list) {
		 rc = onep_policy_op_list_destroy(&pmap_op_list);
		 if (ONEP_OK != rc) {
			 fprintf(stderr, "\nError in destroying pmap Op List : %d, %s", rc, onep_strerror(rc));
		 }
	 }
	
	 rc = onep_policy_pmap_op_list_new(&pmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in getting Network Application : %d, %s", rc, onep_strerror(rc));
	 }
	
	 rc = onep_policy_pmap_op_delete(pmap_op_list, pmap_handle, &pmap_op);
	 if(rc != ONEP_OK) {
		fprintf(stderr, "\nError in deleting pmap : %d, %s", rc, onep_strerror(rc));
	
	 }
	
	 rc = onep_policy_op_add_network_element(pmap_op_list, ne);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in sending pmap op list to network element : %d, %s", rc, onep_strerror(rc));
	
	 }
	
	 rc = onep_policy_op_update(pmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in updating pmap op list : %d, %s", rc, onep_strerror(rc));
	
	 }

	 //Removing class map
	 if(cmap_op_list) {
		 rc = onep_policy_op_list_destroy(&cmap_op_list);
		 if (ONEP_OK != rc) {
			fprintf(stderr, "\nError in destroying cmap Op List : %d, %s", rc, onep_strerror(rc));
		 }
	 }
	
	 rc = onep_policy_cmap_op_list_new(&cmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in getting cmap op list : %d, %s", rc, onep_strerror(rc));
		 
	 }
	
	 rc = onep_policy_cmap_op_delete(cmap_op_list, cmap_handle, &cmap_op);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in deleting cmap : %d, %s", rc, onep_strerror(rc));
		 
	 }
	
	 rc = onep_policy_op_add_network_element(cmap_op_list, ne);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in sending op list to network element : %d, %s", rc, onep_strerror(rc));
		 
	 }
	
	 rc = onep_policy_op_update(cmap_op_list);
	 if(rc != ONEP_OK) {
		 fprintf(stderr, "\nError in updating cmap op list : %d, %s", rc, onep_strerror(rc));
		 
	 }

   cleanup:
                
      if(target_op_list) {
    	  destroy_rc = onep_policy_op_list_destroy(&target_op_list);
          if(destroy_rc != ONEP_OK) {
        	  fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s",
              destroy_rc, onep_strerror(destroy_rc));
          }
      }
      
      if(acl) {
         destroy_rc = onep_acl_delete_acl(&acl);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_acl_delete_acl: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(global_cap) {
         destroy_rc = onep_policy_global_cap_destroy(&global_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_global_cap_destroy: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(filter_cap) {
         destroy_rc = onep_policy_cap_filter_destroy(&filter_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_cap_filter_destroy: %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(tables) {
         destroy_rc = onep_collection_destroy(&tables);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in destroy tables : %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intfs) {
         destroy_rc = onep_collection_destroy(&intfs);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intfs : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intf_filter) {
         destroy_rc = onep_interface_filter_destroy(&intf_filter);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intf_filter : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }
	pthread_mutex_lock(&mut);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mut);
	pthread_exit(NULL);
}

void start_thread(pthread_t *pthr, onep_if_name *intf_name){
	max_sec = 0;
	max_nanosec = 0;
	min_sec = 0;
	min_nanosec = 0;
	brake_value = 0;
	//count = 0;
	m_packet = 1;
	pthread_create(pthr, NULL, thread_program_run, intf_name);
	pthread_mutex_lock(&mut);
	pthread_cond_wait(&cond, &mut);
	pthread_mutex_unlock(&mut);
}

/* Main application  */
int main (int argc, char* argv[]) {
	onep_session_handle_t* sh;
	onep_if_name intf_name;
	//onep_network_interface_t* intf;	
	onep_status_t rc;
	//onep_if_name name;

	pthread_t pthr;
	char kb_buff[9];
	int kb_read_result = 0, error;
	int cancel = 0;
	int i = 0;
	int intf_range = 0;
	int mean = 0;
	
	//assign argc and argv to global in order for
	//thread to access
	gargc = argc;
	gargv = argv;
	saved_stdout = stdout;
	unlink("dropped_packets_log.txt");
	

	/*validate and parse the input. */
	   if (parse_options_datapath(gargc, gargv) == 1) {
	      fprintf(stderr, "Usage: %s %s %s %s %s\n",
		 gargv[0],
		 get_usage_required_options(),
		 get_usage_required_options_datapath(),
		 get_usage_optional_options_datapath(),
		 get_usage_optional_options());
	      return EXIT_FAILURE;
	   }

	   if (strcasecmp(get_transport_type(), "tipc") != 0
	      || strcmp(get_transport_type(), "2") != 0) {
	      prompt_authentication(); //username
	      prompt_client_key_passphrase();//password
	   }
	   
	   proto = atoi(get_protocol());
	   strncpy(intf_name, get_interface(), ONEP_IF_NAME_SIZE - 1);
	
	/* Connect to the Network Element */
	   sh = connect_network_element(
		       get_element_hostname(),
		       get_login_username(),
		       get_login_password(),
		       "com.cisco.onepapp.datapath",
		       get_transport_type(),
		       &ne);

	   if (!sh) {
	      fprintf(stderr, "\n*** create_network_connection fails ***\n");
	      return ONEP_FAIL;
	   }
	    printf("\n Network Element CONNECT SUCCESS \n");

	//start running thread
	start_thread(&pthr, &intf_name);	
	
	while(cancel != 1){
		kb_read_result = read(STDIN_FILENO, &kb_buff, sizeof(kb_buff)-1);
		if(kb_read_result > 0){
			//wait until thread is dead
			brake_value = 1;
			pthread_mutex_lock(&mut);
			pthread_cond_wait(&cond, &mut);
			pthread_mutex_unlock(&mut);
			//print some statistical information
			printf("\n\n#########MEAN: %d sec %.9ld nsec#########\n", t_sum.tv_sec/count, t_sum.tv_nsec/count);
			printf("#########MAX:  %d sec %.9ld nsec#########\n", max_sec, max_nanosec);
			printf("#########MIN:  %d sec %.9ld nsec#########\n", min_sec, min_nanosec);
			switch (kb_buff[0]){
				case 'D': //case: change drop rate
					if(pthread_join(pthr, NULL)){
						fprintf(stderr, "Error in pthread_join: ", strerror(error));				
					}
					while(1){
						//get new value
						printf("Enter value between 0 and 100%\nEnter 100 to drop all the packets\nEnter 0 to stop the packets dropping\n");
						kb_read_result = read(STDIN_FILENO, &kb_buff, sizeof(kb_buff)-1);
							if(kb_read_result > 0){					  
							sscanf(kb_buff, "%d", &drop_rate);
							if(drop_rate < 0 || drop_rate > 100){
								printf("Wrong range. Try again\n");
						     	 	continue;
							}
							else {
								drop_rate = 100 - drop_rate;
								printf ("\n\nDrop rate: let %d packets to flow and %d will be dropped\n\n", drop_rate, (100-drop_rate));
								sleep(2);
								break;
							}
						}
					}
					start_thread(&pthr, &intf_name);
					break;

				case 'E': //exit
					cancel = 1;
					if(pthread_join(pthr, NULL)){
						fprintf(stderr, "Error in pthread_join: ", strerror(error));				
					}
					printf("\nDone. Goodbye!\n");
					break;
				case 'I': //change interface
					if(pthread_join(pthr, NULL)){
						fprintf(stderr, "Error in pthread_join: ", strerror(error));				
					}
					//get number of interface starting from 0
					intf_range = display_intf_list(stderr, 0, 0, NULL);
					kb_read_result = read(STDIN_FILENO, &kb_buff, sizeof(kb_buff)-1);
					if(kb_read_result > 0){	
					    sscanf(kb_buff, "%d", &i);
					    if(i >= 0 && i < intf_range){ //set interface
						    display_intf_list(stderr,1,i, &intf_name);
						}
						else{
						    write(STDOUT_FILENO, "Wrong interface\n", 15);
						}
					}
					//start thread
					start_thread(&pthr, &intf_name);
					break;
				default:
					printf("Undefined\n");
					break;	
			}
		}
	}
	close(fd_dropped);
 	_exit(0);
}


