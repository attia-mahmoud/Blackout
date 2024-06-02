# Event to detect blackout packets
event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack:count, len: count, payload: string) {
	if ("MX2" in payload) {
		print fmt ("There is a blackout packet!");
	}
}

# Event to handle new connections
event new_connection(c: connection) {
    if (c$id$orig_h == 192.168.1.4 && port_to_count(c$id$orig_p) == 2004) {
        print fmt("Connection detected to 192.168.1.4:2004 from %s:%d", c$id$resp_h, c$id$resp_p);
    } 
    else if (c$id$resp_h == 192.168.1.4 && port_to_count(c$id$resp_p) == 2004) {
        print fmt("Connection detected to 192.168.1.4:2004 from %s:%d", c$id$orig_h, c$id$orig_p);
    }
}
