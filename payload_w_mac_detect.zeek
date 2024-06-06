@load policy/protocols/conn/mac-logging

# Event to detect blackout packets
event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack:count, len: count, payload: string) {
	if ("MX2" in payload && c$orig$l2_addr != "00:0b:29:76:f7:7a") {
		print fmt ("Adversary has sent a blackout packet from %s:%d! From MAC: %s to MAC: %s", c$id$resp_h,  c$id$resp_p, c$resp$l2_addr,  c$orig$l2_addr);
		local result = Exec::run(Exec::Command($cmd="python3 /home/chase/clear_logs.py"));
		local results = Exec::run(Exec::Command($cmd="bash /home/chase/happy.sh"));
	}
}

# Event to detect new TCP connections to the PLC
event new_connection(c: connection) {

    if (c$id$orig_h == 192.168.1.4 && port_to_count(c$id$orig_p) == 2004) {
        #print fmt("TCP connection detected to PLC at 192.168.1.4:2004 from %s:%s:%d", c$id$resp_h, c?$resp_l2_addr,c$id$resp_p);
#        print fmt("TCP connection detected to PLC at 192.168.1.4:2004 from %s:%d with MAC: %s", c$id$resp_h, c$id$resp_p, c$resp$l2_addr);
    } 
    else if (c$id$resp_h == 192.168.1.4 && port_to_count(c$id$resp_p) == 2004) {
 #       print fmt("TCP connection detected to PLC at 192.168.1.4:2004 from %s:%d with MAC: %s", c$id$orig_h, c$id$orig_p, c$resp$l2_addr);
    }
}

# Event to detect new connections to the VNC
event new_connection(c: connection) {
#    if (c$id$orig_h == 192.168.1.2 && port_to_count(c$id$orig_p) == 5900) {
#        print fmt("VNC connection detected to HMI at 192.168.1.2:5900 from %s:%d with MAC: %s", c$id$resp_h, c$id$resp_p, c$resp$l2_addr);
#    } 
    if (c$id$resp_h == 192.168.1.2 && port_to_count(c$id$resp_p) == 5900 && c$orig$l2_addr == "88:c9:b3:b0:8c:52") {
	print fmt("Operator has connected to VNC!");
    }
    if (c$id$resp_h == 192.168.1.2 && port_to_count(c$id$resp_p) == 5900 && c$orig$l2_addr != "88:c9:b3:b0:8c:52") {
        print fmt("Strange VNC connection detected to HMI (192.168.1.2:5900) from %s:%d. From MAC: %s to MAC: %s", c$id$orig_h, c$id$orig_p, c$resp$l2_addr, c$orig$l2_addr);
        local result = Exec::run(Exec::Command($cmd="python3 /home/chase/clear_big_logs.py"));
    }
}

# Event to detect connections with XP-Builder
event new_connection(c: connection) {
    if (c$id$orig_h == 192.168.1.2 && port_to_count(c$id$orig_p) == 2143) {
        print fmt("Connection with XP-Builder detected to HMI (192.168.1.2:2143) from %s:%d. From MAC: %s to MAC: %s", c$id$resp_h,  c$id$resp_p, c$resp$l2_addr, c$orig$l2_addr);
    } 
    else if (c$id$resp_h == 192.168.1.2 && port_to_count(c$id$resp_p) == 2143) {
        print fmt("Connection with XP-Builder detected to HMI (192.168.1.2:2143) from %s:%d From MAC: %s to MAC: %s", c$id$resp_h, c$id$resp_p, c$resp$l2_addr, c$orig$l2_addr);
    }
}


# Event detected to VLAN switch access
event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack:count, len: count, payload: string) {
#    if (c$id$resp_h == 192.168.0.12) {
#        print fmt("Connection with VLAN switch detected at 192.168.0.12 from %s:%d", c$id$resp_h, c$id$resp_p);
#    } 
    if ("/qvlan.js" in payload) {
    	print fmt ("Adversary is accessing the VLAN settings of %s! From MAC: %s", c$id$resp_h, c$resp$l2_addr);
    }
    if ("/ConfigRpm.htm" in payload) {
    	print fmt ("Adversary is uploading a custom configuration file for %s! From MAC: %s", c$id$resp_h, c$resp$l2_addr);
    }
}
