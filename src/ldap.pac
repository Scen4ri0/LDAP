%include binpac.pac
%include zeek.pac

%extern{
	#include "events.bif.h"
%}

analyzer LDAP withcontext {
	connection: LDAP_Conn;
	flow:       LDAP_Flow;
};

# Our connection consists of two flows, one in each direction.
connection LDAP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = LDAP_Flow(true);
	downflow = LDAP_Flow(false);
};


%include ldap-protocol.pac

# Now we define the flow:
flow LDAP_Flow(is_orig: bool) {

	datagram = LDAP_PDU(is_orig) withcontext(connection, this);
};

%include ldap-analyzer.pac