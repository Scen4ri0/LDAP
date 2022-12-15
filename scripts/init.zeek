module LDAP;

@load ./consts.zeek

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                 time    &log;
		uid:                string  &log;
		id:                 conn_id &log;
        messageid:          count   &log;
		protocolOp:         count   &log;
		version:         	count   &log;
		resultCode:         count   &log;
		scope:        	 	count   &log;
		derefAliases:       count   &log;
		sizeLimit:         	count   &log;
		timeLimit:         	count   &log;
		typesOnly:         	count   &log;	
	};

	global log_ldap: event(rec: Info);
}


event zeek_init() &priority=5
	{
	Log::create_stream(LDAP::LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);
	}

event ldap_bind_request(c: connection, messageid: count, protocolOp: count, version: count);
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp_types(protocolOp);
	info$version  = version;
	Log::write(LDAP::LOG, info);
	}

event ldap_bind_responce(c: connection, messageid: count, protocolOp: string, resultCode: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp_types(protocolOp);
	info$resultCode  = resultCode_types(resultCode);

	Log::write(LDAP::LOG, info);
	}

event ldap_unbind_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp_types(protocolOp);

	Log::write(LDAP::LOG, info);
	}

event ldap_search_request(c: connection, messageid: count, protocolOp: count, scope: count, derefAliases: count, sizeLimit: count, timeLimit: count, typesOnly: bool%)
	{
	local info: Info;
	info$ts  			= network_time();
	info$uid 			= c$uid;
	info$id  			= c$id;
    info$messageid		= messageid;
	info$protocolOp 	= protocolOp_types(protocolOp);
	info$scope 			= Scope_types(scope);
	info$derefAliases 	= DerefAliases_types(derefAliases);
	info$sizeLimit		= sizeLimit;
	info$timeLimit 		= timeLimit;
	info$typesOnly 		= typesOnly;


	Log::write(LDAP::LOG, info);
	}

event ldap_search_result_done(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp 	= protocolOp_types(protocolOp);
	info$resultCode  = resultCode_types(resultCode);

	Log::write(LDAP::LOG, info);
	}
