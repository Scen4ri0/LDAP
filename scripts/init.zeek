module LDAP;

@load ./consts.zeek

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                 time    &log;
		uid:                string  &log;
		id:                 conn_id &log;
        messageid:          count   &log;
		opcode:         	string   &log;
		version:         	count   &log;
		resultCode:         string   &log;
		scope:        	 	string   &log;
		derefAliases:       string   &log;
		sizeLimit:         	count   &log;
		timeLimit:         	count   &log;
		typesOnly:         	count   &log;	
	};

	global log_ldap: event(rec: Info);
}

const ports = {389/tcp};
redef likely_server_ports += { ports };
event zeek_init() &priority=5
	{
	Log::create_stream(LDAP::LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_LDAP, ports);
	}

event ldap_bind_request(c: connection, messageid: count, opcode: count, version: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$opcode  = protocolOp_types[opcode];
	info$version  = version;
	Log::write(LDAP::LOG, info);
	}

event ldap_bind_responce(c: connection, messageid: count, opcode: count, resultCode: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$opcode  = protocolOp_types[opcode];
	info$resultCode  = resultCode_types[resultCode];

	Log::write(LDAP::LOG, info);
	}

event ldap_unbind_request(c: connection, messageid: count, opcode: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$opcode  = protocolOp_types[opcode];

	Log::write(LDAP::LOG, info);
	}

event ldap_search_request(c: connection, messageid: count, opcode: count, scope: count, derefAliases: count, sizeLimit: count, timeLimit: count, typesOnly: count)
	{
	local info: Info;
	info$ts  			= network_time();
	info$uid 			= c$uid;
	info$id  			= c$id;
    info$messageid		= messageid;
	info$opcode	= protocolOp_types[opcode];
	info$scope 			= Scope_types[scope];
	info$derefAliases 	= DerefAliases_types[derefAliases];
	info$sizeLimit		= sizeLimit;
	info$timeLimit 		= timeLimit;
	info$typesOnly 		= typesOnly;


	Log::write(LDAP::LOG, info);
	}

event ldap_search_result_done(c: connection, messageid: count, opcode: count, resultCode: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$opcode 	= protocolOp_types[opcode];
	info$resultCode  = resultCode_types[resultCode];

	Log::write(LDAP::LOG, info);
	}
