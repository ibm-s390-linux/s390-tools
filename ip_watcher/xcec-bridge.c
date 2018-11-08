/*
 * xcec-bridge - HiperSockets Network Concentrator
 *
 * Parameters:
 *   also_unicast     - uni-, multi-, broadcast is bridged
 *   <no parameters>  - multi-, broadcast is bridged
 *   only broadcast   - only broadcast is bridged
 *
 * Copyright IBM Corp. 2003, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <errno.h>
#include <features.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/zt_common.h"

/* a signal causes the interfaces to be re-checked */


#define LOGGING_FACILITY LOG_LOCAL0

#define UPDATE_SIGNAL SIGUSR1

#define DEV_NAME_SIZE IFNAMSIZ

#define BUFFER_LEN 65536

int so_sndbuf=(8*1024*1024);

int do_unicast_bridging=0;
int do_multicast_bridging=1;
int do_broadcast_bridging=0;

struct int_sock {
#define I_S_FEATURE_PASSTHROUGH	0x01
	int features;
	int i_fd;
	int o_fd;
	char dev_name[DEV_NAME_SIZE];
	int mtu_warning;

	struct int_sock *next;
};

fd_set work_fd_set; /* used in and changed by select */

struct set {
	fd_set fds;
	int highest_fd;

	struct int_sock *i_s_list;
};

struct set select_set;

volatile int update_interface_trigger=0;

int open_incoming_socket(char *dev_name)
{
	int fd,retval;
	struct sockaddr_ll sock_addr;
	struct ifreq if_req;
	struct packet_mreq mc_req;

	/* we want to receive everything. we filter out stuff that we
	 * don't forward by ourselves */
	fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (fd==-1) {
		syslog(LOG_ERR,"can't open raw packet socket, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		return -1;
	}

	strncpy(if_req.ifr_name,dev_name,DEV_NAME_SIZE);
	retval=ioctl(fd,SIOCGIFINDEX,&if_req);
	if (retval==-1) {
		syslog(LOG_ERR,"can't ioctl on raw packet socket, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	sock_addr.sll_protocol=htons(ETH_P_ALL);
	sock_addr.sll_ifindex=if_req.ifr_ifindex;
	sock_addr.sll_family=AF_PACKET;
	retval=bind(fd,(struct sockaddr *)&sock_addr,
		    sizeof(struct sockaddr_ll));
	if (retval==-1) {
		syslog(LOG_ERR,"can't bind packet raw packet socket to " \
		       "interface %s -- it will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	mc_req.mr_ifindex=if_req.ifr_ifindex;
	mc_req.mr_type=PACKET_MR_ALLMULTI;
	mc_req.mr_alen=0;
	retval=setsockopt(fd,SOL_SOCKET,PACKET_ADD_MEMBERSHIP,
			  &mc_req,sizeof(struct packet_mreq));
	if (retval==-1) {
		syslog(LOG_ERR,"can't set socket options to join all " \
		       "multicast groups -- multicast may not be " \
		       "forwarded from %s: %s",dev_name,strerror(errno));
	}

	return fd;
}

int open_outgoing_socket(char *dev_name)
{
	int fd,retval;
	int val;

	fd=socket(PF_INET,SOCK_RAW,IPPROTO_RAW);
	if (fd==-1) {
		syslog(LOG_ERR,"can't open raw inet socket, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		return -1;
	}


	/* IP_HDRINCL should be set by the stack already, we'll set
	 * it nevertheless */
	val=1;
	retval=setsockopt(fd,SOL_IP,IP_HDRINCL,&val,sizeof(int));
	if (retval==-1) {
		syslog(LOG_ERR,"can't set IP_HDRINCL on raw inet socket, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	/* we bind the socket to the device */
	retval=setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,
			  dev_name,strlen(dev_name)+1);
	if (retval==-1) {
		syslog(LOG_ERR,"can't bind raw inet socket to device, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	/* get max socket buffer */
	retval=setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&so_sndbuf,sizeof(int));
	if (retval==-1) {
		syslog(LOG_ERR,"can't set socket buffer size, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	/* and enable broadcast on the socket */
	val=1;
	retval=setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&val,sizeof(int));
	if (retval==-1) {
		syslog(LOG_ERR,"can't enable broadcast on raw inet socket, " \
		       "interface %s will not be used: %s",
		       dev_name,strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int interface_in_list(struct int_sock *item,struct int_sock *list)
{
	for (;list;list=list->next) {
		if (!strncmp(item->dev_name,list->dev_name,DEV_NAME_SIZE)) {
			return 1;
		}
	}
	return 0;
}


int read_sys(struct int_sock **nlist)
{
	DIR *qdir;
	FILE *qfile;
	struct dirent *qde;
	char fname[256];
	char *tmp;
	char if_name[256];
	char rtr[256];
	struct int_sock *is = NULL;
	int i;

	qdir = opendir("/sys/devices/qeth");
	if (!qdir) {
		syslog(LOG_ERR,"failed to open directory /sys/devices/qeth");
		return errno;
	}

	while ((qde = readdir(qdir))) {
		if ((qde->d_type == DT_DIR) && (qde->d_name[0] != '.')) {
			strcpy(fname, "/sys/devices/qeth/");
			strcat(fname, qde->d_name);
			strcat(fname, "/if_name");
			qfile = fopen(fname, "r");
			if (!qfile) {
				continue;
			}
			tmp = if_name;
			while ((i = fgetc(qfile)) != EOF) {
				if ((char)i == '\n') {
					*tmp = 0;
					break;
				} else {
					*tmp = (char)i;
				}
				tmp++;
			}
			*tmp = 0;
			fclose(qfile);

			strcpy(fname, "/sys/devices/qeth/");
			strcat(fname, qde->d_name);
			strcat(fname, "/route4");
			qfile = fopen(fname, "r");
			if (!qfile) {
				continue;
			}
			tmp = rtr;
			while ((i = fgetc(qfile)) != EOF) {
				if ((char)i == '\n') {
					*tmp = 0;
					break;
				} else {
					*tmp = (char)i;
				}
				tmp++;
			}
			*tmp = 0;
			fclose(qfile);

			if (!strstr(rtr, "multicast") &&
			    !strstr(rtr, "connector"))
				continue;

			is = malloc(sizeof(struct int_sock));
			if (!is) {
				syslog(LOG_ERR,"no memory while reading from "\
					"/sys/devices/qeth some interface"\
					"might not be used");
				continue;
			}

			/* as soon as we have one interface echoeing back
			 * broadcasts to us, we don't bridge broadcast
			 * traffic
			 */
			if (!(strstr(rtr, "connector+") ||
			      strstr(rtr, "multicast router+")))
				do_broadcast_bridging=0;

			is->mtu_warning=0;
			strncpy(is->dev_name, if_name, DEV_NAME_SIZE);
			if (!strncmp(if_name,"hsi",3)) {
				is->features=I_S_FEATURE_PASSTHROUGH;
			}

			is->next = *nlist;
			*nlist = is;
		}
	}

	closedir(qdir);
	return 0;
}

void update_interfaces()
{
	struct int_sock *new_list=NULL;
	struct int_sock *i=NULL,*j,*prev;
	struct int_sock *new_int=NULL;
	int i_fd,o_fd;

	/* if all interfaces are '+'-interfaces, we bridge broadcast */
	do_broadcast_bridging=1;
	update_interface_trigger=0;
	syslog(LOG_DEBUG,"rechecking interfaces");

	if (read_sys(&new_list))
		return;

	for (i=select_set.i_s_list;i;i=i->next) {
		if (!interface_in_list(i,new_list)) {
			/* remove interface i */
			j=select_set.i_s_list;
			prev=NULL;
			while (j) {
				if (!strncmp(j->dev_name,i->dev_name,
					     DEV_NAME_SIZE)) {
					if (!prev) {
						select_set.i_s_list=j->next;
					} else {
						prev->next=j->next;
					}
					prev=j;
					j=j->next;
					free(j);
				} else {
					j=j->next;
				}
			}
			/* and close the socket */
			close(i->i_fd);
			close(i->o_fd);
			syslog(LOG_INFO,"removed interface %s",i->dev_name);
		}
	}

	for (i=new_list;i;i=i->next) {
		if (!interface_in_list(i,select_set.i_s_list)) {
			/* add interface i */
			new_int=malloc(sizeof(struct int_sock));
			if (!new_int) {
				syslog(LOG_ERR,"can't add interface %s -- " \
				       "no memory",i->dev_name);
				continue;
			}

			i_fd=open_incoming_socket(i->dev_name);
			if (i_fd==-1) {
				free(new_int);
				continue;
			}

			o_fd=open_outgoing_socket(i->dev_name);
			if (o_fd==-1) {
				close(i_fd);
				free(new_int);
				continue;
			}

			strncpy(new_int->dev_name,i->dev_name,DEV_NAME_SIZE);
			new_int->i_fd=i_fd;
			new_int->o_fd=o_fd;
			new_int->features=i->features;
			new_int->next=select_set.i_s_list;
			select_set.i_s_list=new_int;
			syslog(LOG_INFO,"added interface %s",i->dev_name);
		}
	}

	/* kill temporary new_list */
	while (new_list) {
		i=new_list->next;
		free(new_list);
		new_list=i;
	}

	/* prepare the fd_set for select */
	FD_ZERO(&select_set.fds);
	for (i=select_set.i_s_list;i;i=i->next) {
		FD_SET(i->i_fd,&select_set.fds);
		select_set.highest_fd=(i->i_fd>select_set.highest_fd)?
			i->i_fd:select_set.highest_fd;
	}
}

void process_packet(struct int_sock *i_s)
{
	int retval;
	char buffer[BUFFER_LEN];
	int buffer_len;
	struct int_sock *i_s_item;
	struct sockaddr_ll s_ll;
	struct sockaddr_in s_in;
	socklen_t sll_len;

	sll_len=(socklen_t)sizeof(struct sockaddr_ll);
	buffer_len=recvfrom(i_s->i_fd,buffer,BUFFER_LEN,0,
			    (struct sockaddr *)&s_ll,&sll_len);
	if (buffer_len==-1) {
		syslog(LOG_WARNING,"recvfrom failed on %s: %s\n",
		       i_s->dev_name,strerror(errno));
		return;
	}

	/* nothing read */
	if (buffer_len==0)
		return;

	/* no packets that came from our own stack... that could lead to
	 * traffic loops */
	if (s_ll.sll_pkttype==PACKET_OUTGOING)
		return;

	/* only do unicast bridging when required */
	if ( (s_ll.sll_pkttype==PACKET_HOST) &&
	     (!do_unicast_bridging) )
		return;

	/* only do multicast bridging when required */
	if ( (s_ll.sll_pkttype==PACKET_MULTICAST) &&
	     (!do_multicast_bridging) )
		return;

	/* broadcast is critical, see comment above */
	if (!do_broadcast_bridging) {
		if (s_ll.sll_pkttype==PACKET_BROADCAST)
			return;
	}

	/* only do v4 at this time */
	if (s_ll.sll_protocol!=ETH_P_IP)
		return;

	/* forward buffer to each interface ... */
	for (i_s_item=select_set.i_s_list;i_s_item;i_s_item=i_s_item->next) {
		/* ... but i_s */
		if (i_s_item==i_s) continue;

		s_ll.sll_ifindex=0;
		s_in.sin_family=AF_INET;
		s_in.sin_port=0;
		if (s_ll.sll_pkttype==PACKET_BROADCAST) {
			s_in.sin_addr.s_addr=INADDR_BROADCAST;
		} else {
			memcpy(&s_in.sin_addr, &buffer[16 + ETH_HLEN], 4);
		}

		retval=sendto(i_s_item->o_fd, buffer + ETH_HLEN,
				buffer_len - ETH_HLEN, 0,
				(struct sockaddr *)&s_in,
				sizeof(struct sockaddr_in));
		if (retval==-1) {
			if ( (errno==EMSGSIZE) && (!i_s_item->mtu_warning) ) {
				syslog(LOG_WARNING,"MTU of %s too small " \
				       "to forward packet with size of %i" \
				       " -- won't show warning again.",
				       i_s_item->dev_name,buffer_len);
				i_s_item->mtu_warning=1;
			} else {
				syslog(LOG_WARNING,"sendto failed on %s: " \
				       "%s\n",i_s_item->dev_name,
				       strerror(errno));
			}
		} else if (retval != (buffer_len - ETH_HLEN)) {
			syslog(LOG_WARNING,"sendto sent only %i instead " \
			       "of %i bytes on %s\n",
			       retval,buffer_len,i_s->dev_name);
		}
	}
}

void action_handler(int UNUSED(s))
{
	update_interface_trigger=1;
	syslog(LOG_DEBUG,"signal caught");
	/* select will return, interfaces will be re-checked */
}

int main(int argc,char *argv[]) {
	struct int_sock *i_s;
	int retval,r;
	struct sigaction s_a;

	if ( (argc>1) && (!strncmp(argv[1],"also_unicast",12)) ) {
		do_unicast_bridging=1;
	} else
	if ( (argc>1) && (!strncmp(argv[1],"only_broadcast",14)) ) {
		do_multicast_bridging=0;
	}

	openlog("xcec-bridge",LOG_NDELAY,LOGGING_FACILITY);

	FD_ZERO(&select_set.fds);
	select_set.i_s_list=NULL;
	select_set.highest_fd=0;

	s_a.sa_handler=action_handler;
	if (sigemptyset(&s_a.sa_mask)) {
		syslog(LOG_ERR,"problem in sigemptyset: %s -- exiting",
		       strerror(errno));
		return 1;
	}
	s_a.sa_flags=0;
	retval=sigaction(UPDATE_SIGNAL,&s_a,NULL);

	if (sigemptyset(&s_a.sa_mask)) {
		syslog(LOG_ERR,"problem in sigemptyset: %s -- exiting",
		       strerror(errno));
		return 1;
	}
	if (sigaddset(&s_a.sa_mask,UPDATE_SIGNAL)) {
		syslog(LOG_ERR,"problem in sigaddset: %s -- exiting %s",
		       argv[0],strerror(errno));
		return 1;
	}
	r=sigprocmask(SIG_BLOCK,&s_a.sa_mask,NULL);
	if (r) {
		syslog(LOG_ERR,"sigprocmask: %s",strerror(errno));
	}

	syslog(LOG_INFO,"*** started ***");

	update_interfaces();

	while (1) {
		r=sigprocmask(SIG_UNBLOCK,&s_a.sa_mask,NULL);
		if (r) {
			/* while blocked: */
			update_interfaces();

			syslog(LOG_INFO,"sigprocmask (unblock): %s",
			       strerror(errno));
			/* try until sigprocmask is not interrupted by a
			 * signal */
			while (sigprocmask(SIG_UNBLOCK,&s_a.sa_mask,NULL)) ;
		}

		memcpy(&work_fd_set,&select_set.fds,sizeof(fd_set));
		retval=select(select_set.highest_fd+1,&work_fd_set,
		     	      NULL,NULL,NULL);
		r=sigprocmask(SIG_BLOCK,&s_a.sa_mask,NULL);
		if (r) {
			syslog(LOG_INFO,"sigprocmask (block): %s",
			       strerror(errno));
			/* try until sigprocmask is not interrupted by a
			 * signal */
			while (sigprocmask(SIG_BLOCK,&s_a.sa_mask,NULL)) ;

			/* when blocked: */
			update_interfaces();
		}

		/* a signal came in after we unblocked
		 * or before we blocked? we may process one packet before
		 * the list gets updated, but we do this check here never-
		 * theless in order to not catch a signal during some
		 * system call in update_interfaces
		 */
		if (update_interface_trigger) {
			update_interfaces();
		}

		if (retval==-1) {
			if (errno==EINTR) {
				update_interfaces();
			} else if (errno) {
				syslog(LOG_WARNING,"select returned with %s",
				       strerror(errno));
			}
			continue; /* fds are undefined -> no packets came
				     in at this time */
		}

		/* check all fds regardless of retval */
		for (i_s=select_set.i_s_list;i_s;i_s=i_s->next) {
			if (FD_ISSET(i_s->i_fd,&work_fd_set)) {
				process_packet(i_s);
			}
		}
	}

	/* cleanup... no. */
}
