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


%include ldap-strings.pac
%include ldap-protocol.pac

# Now we define the flow:
flow LDAP_Flow(is_orig: bool) {

	# ## TODO: Determine if you want flowunit or datagram parsing:

	# Using flowunit will cause the anlayzer to buffer incremental input.
	# This is needed for &oneline and &length. If you don't need this, you'll
	# get better performance with datagram.

	# flowunit = BROWSER_PDU(is_orig) withcontext(connection, this);

};

%include ldap-analyzer.pac