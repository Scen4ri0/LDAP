#pragma once

#include "events.bif.h"


#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "ldap_pac.h"

namespace zeek::analyzer::ldap {

class LDAP: public tcp::TCP_ApplicationAnalyzer
{
	public:
 	 LDAP(Connection* conn);
 	 virtual ~LDAP();

 // Overriden from Analyzer.
 	virtual void Done();
 
 	virtual void DeliverStream(int len, const u_char* data, bool orig);
 	virtual void Undelivered(uint64_t seq, int len, bool orig);

 // Overriden from tcp::TCP_ApplicationAnalyzer.
 	virtual void EndpointEOF(bool is_orig);
 

 	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
  	{ return new LDAP(conn); }

	protected:
 	 binpac::LDAP::LDAP_Conn* interp;
 	 bool had_gap;
};

} // namespace analyzer::*
