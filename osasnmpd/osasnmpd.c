/*
 * osasnmpd - IBM OSA-Express network card SNMP subagent
 *
 * OSA-E subagent main module
 *
 * This subagent extends the net-snmp master agent to support
 * the Direct SNMP feature of zSeries OSA-E network cards. 
 * net-snmp AgentX support must be enabled to allow the
 * subagent connecting to the master agent (snmpd).  
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>
#include <linux/version.h>
#include <signal.h>
#include <sys/utsname.h>

#include "lib/zt_common.h"

#include "ibmOSAMibUtil.h"
#include "ibmOSAMib.h"

/* osasnmpd version */
#define COPYRIGHT "Copyright IBM Corp. 2003, 2017"

/* ptr to OSA Express MIB information stored in linked lists */
extern TABLE_OID* oid_list_head;

sig_atomic_t keep_running = 1; 
sig_atomic_t interfaces_changed = 0;

/* signal handler for SIGTERM or SIGINT */ 
RETSIGTYPE
stop_server(int UNUSED(a))
{
	keep_running = 0;
}

/* signal handler for SIGUSR1 
 * which is send by the kernel if the interface information changes
		 */
RETSIGTYPE
on_interfaces_changed( int UNUSED(a) )
{
	interfaces_changed++;
}


static void
sysfs_register()
{
	int sys_fd;
	char buf[10] = {0, };
	
	sys_fd = open( QETH_SYSFILE, O_WRONLY );
        if (sys_fd < 0) {
		fprintf(stderr, "open(%s) failed - reason %s\n",
			QETH_SYSFILE, strerror( errno ) );
		exit(1);
	}
	sprintf(buf, "%d", QETH_UPDATE_MIB_SIGNAL);
	/* register our process to receive SIGUSR1 on interface changes */
	if(write(sys_fd, buf, 10) < 0){
		fprintf(stderr, "registration with qeth driver failed - "
			"reason %s\n", strerror( errno ) );
		close(sys_fd);
		exit(1);
	}
	close(sys_fd);
}

static void
sysfs_unregister()
{
	int sys_fd;
	
	sys_fd = open( QETH_SYSFILE, O_WRONLY );
        if (sys_fd < 0) {
		fprintf(stderr, "open(%s) failed - reason %s\n",
			QETH_SYSFILE, strerror( errno ) );
		exit(1);
	}
	/* unregister our process to receive SIGUSR1 on interface changes */
	if(write(sys_fd, "unregister", 11) < 0){
		fprintf(stderr, "deregistration with qeth driver failed - "
			"reason %s\n", strerror( errno ) );
		close(sys_fd);
		exit(1);
	}
	close(sys_fd);
}

static struct option longopts[] = {
	{"help",no_argument,0,'h'},
	{"version",no_argument,0,'v'},
	{"append",no_argument,0,'A'},
	{"stderrlog",no_argument,0,'L'},
	{"nofork",no_argument,0,'f'},
	{"logfile",required_argument,0,'l'},
	{"pidfile",required_argument,0,'P'},
	{"sockaddr",required_argument,0,'x'},
	{0,0,0,0}
};

#define OPTSTRING "hvALfl:A:P:x:"

/*
 * main routine
 */
int main( int argc, char *argv[] )
{  
	TABLE_OID* li_ptr;
	char oidstr[MAX_OID_STR_LEN];
	char logfile[PATH_MAX + 1];
	char pid_file[PATH_MAX + 1];
	FILE *PID;
	struct sigaction act;
	int res,c,longIndex,rc;
	unsigned char rel_a, rel_b, rel_c;
	struct utsname buf;
	char suffix[sizeof(buf.release)];

	/* default settings, may be overridden by parameters */  
	int std_err_log = 0;     /* 0=turn off stderr logging; 1=turn on */
     	                      /* if turned off; use file logging */
	int dont_zero_log = 0;   /* 0=clear logfile; 1=append to logfile */
	int dont_fork = 0;       /* 0=dont detach from shell; 1=detach */      
	int pid_file_set = 0;
	strcpy( logfile, OSAE_LOGFILE ); /* default log file */

	/* check for parameters */
        while((c = getopt_long(argc, argv, OPTSTRING, longopts,
				&longIndex)) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(0);
			case 'v':
				printf( "osasnmpd: version %s\n",
					RELEASE_STRING);
				printf( "%s\n" , COPYRIGHT );
				exit(0);
			case 'l':
				if (strlen(optarg) > PATH_MAX)
				{
					fprintf( stderr, "osasnmpd: logfile "\
						"path too long (limit %d "\
						"chars)\n", PATH_MAX);
					exit(1);
				}
				strncpy(logfile, optarg, PATH_MAX);
				break;
			case 'A':
				dont_zero_log = 1;
				break;
			case 'L':
				std_err_log=1;
				break;
			case 'f':
				dont_fork = 1;
				break;
			case 'P':
				if (strlen(optarg) > PATH_MAX)
				{
					fprintf( stderr, "osasnmpd: logfile "\
						"path too long (limit %d "\
						"chars)\n", PATH_MAX);
					exit(1);
				}
				strncpy(pid_file,optarg,PATH_MAX);
				pid_file_set = 1;
				break;
			case 'x':
				netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
					NETSNMP_DS_AGENT_X_SOCKET, optarg);
				break;
			default:
				fprintf(stderr, "Try 'osasnmpd --help' for more"
						" information.\n");
				exit(1);
		} /* end switch */
	}  /* end-while */

	while (optind < argc) {
		fprintf(stderr, "osasnmpd: unrecognized argument '%s'\n",
			argv[optind++]);
		fprintf(stderr, "Try 'osasnmpd --help' for more"
				" information.\n");
		exit(1);
	}
	/* detach from shell (default) */
	if (!dont_fork && fork() != 0) 
		exit(0);
 
	/* create a pidfile if requested */ 
	if (pid_file_set) {
		if ((PID = fopen(pid_file, "w")) == NULL) {
			snmp_log_perror("fopen");
			fprintf(stderr, "osasnmpd: cannot create PIDFILE\n");
			exit(1);
		} else {
			fprintf(PID, "%d\n", (int) getpid() );
			fclose(PID);
		}
	}
   
	/* enable logging to stderr or logfile */ 
	if ( !std_err_log ) {
		snmp_disable_stderrlog();
		snmp_enable_filelog( logfile, dont_zero_log );	
	} else {
		snmp_enable_stderrlog();
	}


	snmp_log(LOG_INFO, "IBM OSA-E NET-SNMP 5.1.x subagent version  %s\n",
		 RELEASE_STRING );

	/* make us a agentx client. */
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE,
			       1); 
	
	/* initialize the agent library */
	if ( init_agent("osasnmpd") != 0 ) {
		fprintf(stderr, "osasnmpd: init_agent() failed\n"
			"osasnmpd: check subagent logfile for detailed "
			"information\n" );	      
		exit(1);
	}
	/* initialize OSA Express MIB module here */
	init_ibmOSAMib();  

	/* osasnmpd will be used to read osasnmpd.conf files. */
	init_snmp("osasnmpd");

	act.sa_flags = 0;
	sigemptyset( &act.sa_mask );

	/* handle termination requests (kill -TERM or kill -INT) */
	act.sa_handler = stop_server;
	if( sigaction( SIGTERM, &act, NULL ) < 0 ){
		fprintf(stderr, "sigaction( SIGTERM, ... ) failed - "
			"reason %s\n", strerror( errno ) );
		exit( 1 );
	}

	act.sa_handler = stop_server;
	if( sigaction( SIGINT, &act, NULL ) < 0 ){
		fprintf(stderr, "sigaction( SIGINT, ... ) failed - reason %s\n",
			strerror( errno ) );
		exit( 1 );
	}

	/* handle iterface count change requests ( kill -SIGUSR1 ) */
	act.sa_handler = on_interfaces_changed;
	if( sigaction( SIGUSR1, &act, NULL ) ){
		fprintf(stderr, "sigaction( SIGUSR1, ... ) failed - "
			"reason %s\n", strerror( errno ) );
		exit( 1 );
	}

	rc = uname(&buf);
	if (!rc)
		sscanf(buf.release, "%c.%c.%c-%s",
			&rel_a, &rel_b, &rel_c, suffix);

	if(KERNEL_VERSION(2,6,22) >= KERNEL_VERSION(rel_a, rel_b, rel_c))
		sysfs_register();

	signal(SIGALRM, update_mib_info);
	snmp_log(LOG_INFO, "Initialization of OSA-E subagent successful...\n"); 

	/* subagent main loop, that calls 
	 * agent_check_and_process() in blocking mode 
	 * */
	while(keep_running) {
		if( interfaces_changed > 0 ){
			interfaces_changed = 0;
			alarm(0); /* cancel a potentially scheduled alarm */
			update_mib_info();
			/* reschedule another update_mib_info() since
			   netsnmp does not update the interface counter
			   immediately, but within the next 60 seconds */
			alarm(70); 
		} else	
			agent_check_and_process(1);
	}

	snmp_log(LOG_INFO, "Received TERM or STOP signal...shutting down "
		 "agent...\n"); 

	/* unregister all Toplevel OIDs we support */
	for(li_ptr = oid_list_head; li_ptr->next != NULL; li_ptr =li_ptr->next){
		oid_to_str_conv((oid*)li_ptr->next->pObjid,
				li_ptr->next->length, oidstr);
		snmp_log(LOG_INFO, "unregister Toplevel OID .%s.....", oidstr ); 
		res = unregister_mib(li_ptr->next->pObjid,
				     li_ptr->next->length);
		if (res == MIB_UNREGISTERED_OK)
			snmp_log(LOG_INFO, "successful\n");
		else
			snmp_log(LOG_INFO, "failed %d\n",res);
	}

	if(KERNEL_VERSION(2,6,22) >= KERNEL_VERSION(rel_a, rel_b, rel_c))
		sysfs_unregister();

	snmp_shutdown("osasnmpd");  

	return 0;
}

