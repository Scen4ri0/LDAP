#pragma once

#include "events.bif.h"


#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "ldap_pac.h"

namespace zeek::analyzer::ldap {

class LDAP: public Analyzer {
public:
	LDAP(Connection* conn);
	virtual ~LDAP();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new LDAP(conn);
		}

protected:
	binpac::LDAP::LDAP_Conn* interp;
	};
}
