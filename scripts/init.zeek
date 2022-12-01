module LDAP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                 time    &log;
		uid:                string  &log;
		id:                 conn_id &log;
        messageid:          count   &log;
		protocolOp:          string  &log;
	};

	global log_ldap: event(rec: Info);
}


event zeek_init() &priority=5
	{
	Log::create_stream(LDAP::LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);
	}

event ldap_bind_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}

event ldap_bind_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_unbind_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_search_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_search_result_entry(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_search_result_done(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_modify_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_modify_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_add_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_add_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_delete_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_delete_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_modify_DN_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_modify_DN_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_compare_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_compare_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_abandon_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_search_result_refference(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_extended_request(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_extended_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}
event ldap_intermediate_responce(c: connection, messageid: count, protocolOp: string)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
    info$messageid = messageid;
	info$protocolOp  = protocolOp;

	Log::write(LDAP::LOG, info);
	}

	