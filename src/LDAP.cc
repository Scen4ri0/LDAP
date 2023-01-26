#include "LDAP.h"

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include "zeek/Reporter.h"

#include "zeek/util.h"

#include "events.bif.h"

using namespace zeek::analyzer::ldap;

LDAP::LDAP(Connection* c)

: tcp::TCP_ApplicationAnalyzer("LDAP", c)

 {
 interp = new binpac::LDAP::LDAP_Conn(this);
 
 had_gap = false;
 
 }

LDAP::~LDAP()
 {
 delete interp;
 }

void LDAP::Done()
 {
 
 tcp::TCP_ApplicationAnalyzer::Done();

 interp->FlowEOF(true);
 interp->FlowEOF(false);
 
 }

void LDAP::EndpointEOF(bool is_orig)
 {
 tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
 interp->FlowEOF(is_orig);
 }

void LDAP::DeliverStream(int len, const u_char* data, bool orig)
 {
 LDAP::DeliverStream(len, data, orig);

 assert(TCP());
 if ( TCP()->IsPartial() )
  return;

 if ( had_gap )
  // If only one side had a content gap, we could still try to
  // deliver data to the other side if the script layer can handle this.
  return;

 try
  {
  interp->NewData(orig, data, data + len);
  }
 catch ( const binpac::Exception& e )
  {
  ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
  }
 }

void LDAP::Undelivered(uint64_t seq, int len, bool orig)
 {
 Analyzer::Undelivered(seq, len, orig);
 had_gap = true;
 interp->NewGap(orig, len);
 }