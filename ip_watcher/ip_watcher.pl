#!/usr/bin/perl -w
#
# ip_watcher.pl - HiperSockets Network Concentrator
#
# looks for addresses in the HiperSockets and sets them as Proxy ARP on the
# OSAs. Also adds routing entries towards the HiperSockets interfaces for
# all IP addresses in it

# $OPERATING_MODE="routing_only";
#   ip_watcher just takes care of adapting the routing entries. ipv4
#   forwarding needs to be switched on, if desired mrouted or some multicast
#   routing daemon should run. ip_watcher also sets the proxy arp entries
#   of all hsi addresses on the osa device.
#
# $OPERATING_MODE="full_bridging";
#   this is like routing_only mode, plus xcec-bridge will bridge all
#   kinds of traffic (uni-, multi-, broadcast) between the interfaces,
#   so the stack will not do forwarding.
#   if interfaces come and go, xcec-bridge will be sent a SIGUSR1.
#
# $OPERATING_MODE="mc_bridging";
#   this is a mixture of the above -- ipv4 forwarding of unicast packets
#   is done by the kernel, multi- and broadcast traffic is bridged by
#   xcec-bridge.
#
# $OPERATING_MODE="bc_bridging";
#   this is another mixture of the above -- ipv4 forwarding of unicast
#   packets is done by the kernel, multicast is handled by mrouted or some
#   multicast router, and broadcast traffic is bridged by xcec-bridge.
#
# Copyright 2017 IBM Corp.
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

$OPERATING_MODE="mc_bridging";

$XCEC_BRIDGE="xcec-bridge";
$XCEC_BRIDGE_FULL_PARAM="also_unicast";
$XCEC_BRIDGE_MC_PARAM="";
$XCEC_BRIDGE_BC_PARAM="only_broadcast";

$KILLALL="killall";
$SIGNAL="-USR1";

$MASK_PARAM="netmask";
$DEV_PARAM="dev";
$QETHARP="qetharp -c -q";
$ROUTE_ADD_CMD='route add -net ';
$ROUTE_DEL_CMD='route del -net ';
$PA_ADD_CMD='qethconf parp add -x';
$PA_DEL_CMD='qethconf parp del -x';
# $PA_ADD_CMD='echo add_rxip4';
# $PA_DEL_CMD='echo del_rxip4';

$CHECK_ONLY="no";

$nextarg=0;
if ($#ARGV>=$nextarg) {
	if ($ARGV[$nextarg] eq "--check") {
		$CHECK_ONLY="yes";
		$nextarg++;
	}
}

# if there is a parameter to ip_watcher.pl, the parameter will be the
# Proxy ARP interface (i.e. the outgoing OSA interface). In this case,
# xcec-bridge will not be started, so that only unicast is forwarded.

# eth0 is default OSA interface
if ($#ARGV>=$nextarg) {
	$PA_INTERFACE=$ARGV[$nextarg];
	$START_XCEC_BRIDGE="no";
} else {
	$PA_INTERFACE="";
	$START_XCEC_BRIDGE="yes";
}

$SLEEP_TIME=2;
#$TIME_LIMIT=4;
#@time_array=(time,time-1,time-2);


sub print_list($@)
{
	my($h)=shift;
	my(@a)=@_;
	my($i);
	foreach $i (@a) {
		print "DEBUG ". $h .": ". $i ."\n";
	}
}


# get outgoing OSA interface (connecting the CECs)
sub get_proxy_arp_interface
{
	my($devnos);
	my($chpid);
	my($if_name);
	my($type);
	my($port);
	my($chksum);
	my($prio);
	my($rtr);
	my($rest);

	if (opendir(SYSQETH, "/sys/devices/qeth")) {
		@ALLDEV = grep { /^.+\..+\..+$/ } readdir SYSQETH;
		closedir SYSQETH;

		foreach $DEV (@ALLDEV) {
			open(IFNAME, "</sys/devices/qeth/$DEV/if_name") or next;
			chomp($if_name = readline(IFNAME));
			close(IFNAME);
			open(RTR, "</sys/devices/qeth/$DEV/route4") or next;
			chomp($rtr = readline(RTR));
			close(RTR);
			if ( $if_name =~ /^tr|eth.+/ and $rtr =~ /^multicast.+/ ) {
				$PA_INTERFACE=$if_name;
			}
		}
	} else {
		die "could not get available qeth interfaces\n";
	}

	if ($PA_INTERFACE eq "") {
		die "no multicast router defined or no " .
			"LAN interface specified as parameter.\n";
	}
}

# get all interfaces to poll ip addresses from
sub update_interface_list
{
	my($devnos);
	my($chpid);
	my($if_name);
	my($type);
	my($port);
	my($chksum);
	my($prio);
	my($rtr);
	my($rest);
	my(@if_list)=();

	if (opendir(SYSQETH, "/sys/devices/qeth")) {
		@ALLDEV = grep { /^.+\..+\..+$/ } readdir SYSQETH;
		closedir SYSQETH;

		foreach $DEV (@ALLDEV) {
			open(IFNAME, "</sys/devices/qeth/$DEV/if_name") or next;
			chomp($if_name = readline(IFNAME));
			close(IFNAME);
			open(RTR, "</sys/devices/qeth/$DEV/route4") or next;
			chomp($rtr = readline(RTR));
			close(RTR);
			if ( $rtr =~ /^.+connector.*/ ) {
				push(@if_list,$if_name);
			}
		}
	} else {
		print STDERR "could not get available qeth interfaces\n";
		return ();
	}
	return @if_list
}

# only returns with a maximal frequency
sub limit_frequency
{
#	my($t_now)=time;
#	my($t_last);
#	my($sleep_time);

#	unshift(@time_array,$t_now);
#	$t_last=pop(@time_array);
#	$sleep_time=$TIME_LIMIT-($t_now-$t_last);
#	if ($sleep_time>0) {
#		sleep($sleep_time);
#	}
	sleep($SLEEP_TIME);
}

# creates a 0x01020304 out of a 1.2.3.4
sub convert_ip_string_to_number($)
{
	my($ip_str)=shift;
	my(@ip);
	my($ip_oct1);
	my($ip_oct2);
	my($ip_oct3);
	my($ip_oct4);

	@ip=split(/\./,$ip_str);

# check for parsing error
	if ($#ip<3) {
		return 0;
	}

	($ip_oct1,$ip_oct2,$ip_oct3,$ip_oct4)=@ip;

	if ( ($ip_oct1<0) || ($ip_oct1>255) ||
		($ip_oct2<0) || ($ip_oct2>255) ||
		($ip_oct3<0) || ($ip_oct3>255) ||
		($ip_oct4<0) || ($ip_oct4>255) ) {
		return 0;
	}

	return ($ip_oct1<<24)+($ip_oct2<<16)+($ip_oct3<<8)+($ip_oct4);
}

# returns sorted list of ips (in integer format like __u32) of the interface
sub get_ips_on_interface($)
{
	my($interface)=shift;
	my($cmdline)="$QETHARP $interface |";
	my(@ip_list)=();
	my($OUTPUT);
	my($ip);

	unless (open(OUTPUT,$cmdline)) {
		print STDERR "can't open $cmdline";
		return @ip_list;
	}
	while (<OUTPUT>) {
		chop;
		$ip=convert_ip_string_to_number($_);
		if ($ip>0) {
			push(@ip_list,$ip);
		}
	}
	close(OUTPUT) || print STDERR "can't close $cmdline";

	return sort @ip_list;
}

# creates a 1.2.3.4 out of a 0x1020304
sub convert_string_to_ip($)
{
	my($ip)=shift;
	my($ip_oct1);
	my($ip_oct2);
	my($ip_oct3);
	my($ip_oct4);

	$ip_oct4=$ip&0xff;
	$ip>>=8;
	$ip_oct3=$ip&0xff;
	$ip>>=8;
	$ip_oct2=$ip&0xff;
	$ip>>=8;
	$ip_oct1=$ip&0xff;

	return "$ip_oct1.$ip_oct2.$ip_oct3.$ip_oct4";
}

sub __min($$)
{
	my($a)=shift;
	my($b)=shift;
	if ($a<$b) {
		return $a;
	} else {
		return $b;
	}
}

# will create an array of routes in string format
sub get_routes_of_ip_list(@)
{
	my(@ip_list)=@_;
	my(@route_list)=();
	my($ip);
	my($ips_left);
	my($ips_to_combine);
	my($ip_shifted);
	my($ips_found);
	my($end);
	my($order);
	my($mask);
	my($ip_str);
	my($mask_str);
	my($ips_fetched);

	while ($#ip_list>=0) {
		# ips_left is the number of ips left in the list
		$ips_left=$#ip_list;
		$ip=shift(@ip_list);
		$ips_to_combine=1;
		$ip_shifted=$ip;
		while ($ip_shifted%2==0) {
			$ips_to_combine<<=1;
			$ip_shifted>>=1;
			# 0 should never be in the list, anyway...
			if (!$ip_shifted) {
				last;
			}
		}
		# ips_to_combine is a power of 2 and contains the max number
		# of entries that could compressed into one route due to its
		# alignment
		$end=__min($ips_to_combine-1,$ips_left);
		$order=1;
		$ips_found=1;
		while ($ips_found<=$end) {
			# ips_found-1, as we have shifted the first ip
			# already
			if ($ip_list[$ips_found-1]!=$ip+$ips_found) {
				last;
			}
			$ips_found++;
			if ($ips_found==2*$order) {
				$order<<=1;
			}
		}
		# ips_found is now the number of subsequent ips that we can
		# subsum (one of which is shifted already)
		$mask=(-$order)&0xffffffff;
		$ips_fetched=1;
		while ($ips_fetched<$order) {
			$ips_fetched++;
			shift(@ip_list);
		}
		$mask_str=convert_string_to_ip($mask);
		$ip_str=convert_string_to_ip($ip);
		unshift(@route_list,"$ip_str $MASK_PARAM $mask_str");
	}
	
	return @route_list;
}

# will create an array of rxips in string format
sub get_pas_of_ip_list(@)
{
	my(@ip_list)=@_;
	my(@pa_list)=();

	foreach $ip (@ip_list) {
		unshift(@pa_list,"" . sprintf("%08x",$ip));
	}

	return @pa_list;
}

sub is_in_list($@)
{
	my($item)=shift;
	my(@list)=@_;
	my($i);

	foreach $i (@list) {
		if ($i eq $item) {
			return 1;
		}
	}
	return 0;
}

sub exec_for_diff(@)
{
	my($cmd)=shift;
	my($new_list,$old_list)=@_;

	foreach $line (@$new_list) {
		unless (is_in_list($line,@$old_list)) {
			system($cmd . $line . "> /dev/null 2>&1");
		}
	}
}

sub wait_for_changes()
{
# blocking ioctl to be informed on SETIP/DELIPs (once it's implemented in
# hardware) or sleep for X timeunits
}

sub main()
{
	my(@routes)=();
	my(@pas)=();
	my(@new_routes);
	my(@new_pas);
	my(@interface_list)=();
	my(@old_if_list);
	my($interface);
	my(@ip_list);
	my($route);
	my(@tmp_routes);

	get_proxy_arp_interface();

	if ($CHECK_ONLY eq "yes") {
		exit 0;
	}

	if ($START_XCEC_BRIDGE eq "yes") {
		if ($OPERATING_MODE eq "full_bridging") {
			system("$XCEC_BRIDGE $XCEC_BRIDGE_FULL_PARAM &")==0 ||
				die "can't fork $XCEC_BRIDGE: $?";
		}
		if ($OPERATING_MODE eq "mc_bridging") {
			system("$XCEC_BRIDGE $XCEC_BRIDGE_MC_PARAM &")==0 ||
				die "can't fork $XCEC_BRIDGE: $?";
		}
		if ($OPERATING_MODE eq "bc_bridging") {
			system("$XCEC_BRIDGE $XCEC_BRIDGE_BC_PARAM &")==0 ||
				die "can't fork $XCEC_BRIDGE: $?";
		}
	}

	for (;;) {
		if ( ($OPERATING_MODE eq "mc_bridging") ||
		     ($OPERATING_MODE eq "bc_bridging") ||
		     ($OPERATING_MODE eq "full_bridging") ) {
			@old_if_list=@interface_list;
		}
		@interface_list=update_interface_list();
		if ( ($OPERATING_MODE eq "mc_bridging") ||
		     ($OPERATING_MODE eq "bc_bridging") ||
		     ($OPERATING_MODE eq "full_bridging") ) {
			if ( join(':',@old_if_list) ne
				join(':',@interface_list) ) {
				if ($START_XCEC_BRIDGE eq "yes") {
				system("$KILLALL $SIGNAL $XCEC_BRIDGE")==0 ||
					print STDERR "can't send signal " .
					"to $XCEC_BRIDGE to update " .
					"interfaces.\n";
				}
			}
		}
		@new_routes=();
		@new_pas=();
		foreach $interface (@interface_list) {
			@ip_list=get_ips_on_interface($interface);

			@tmp_routes=get_routes_of_ip_list(@ip_list);
			foreach $route (@tmp_routes) {
				unshift(@new_routes,
				   "$route $DEV_PARAM $interface");
			}

			@tmp_pas=get_pas_of_ip_list(@ip_list);
			foreach $pa (@tmp_pas) {
				unshift(@new_pas,
					"$pa $PA_INTERFACE");
			}
		}

		exec_for_diff($ROUTE_ADD_CMD,\@new_routes,\@routes);
		exec_for_diff($ROUTE_DEL_CMD,\@routes,\@new_routes);
		@routes=@new_routes;

		exec_for_diff($PA_ADD_CMD,\@new_pas,\@pas);
		exec_for_diff($PA_DEL_CMD,\@pas,\@new_pas);
		@pas=@new_pas;

		wait_for_changes();
		limit_frequency();
	}
}

main();
