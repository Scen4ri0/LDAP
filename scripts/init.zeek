module LDAP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                 time    &log;
		uid:                string  &log;
		id:                 conn_id &log;
		operation:          string  &log;
        messageid           count   &log;
	};

	global log_browser: event(rec: Info);
}


event zeek_init() &priority=5
	{
	Log::create_stream(LDAP::LOG, [$columns=Info, $ev=log_browser, $path="ldap"]);
	}

event ldap_responce(c: connection, operation: string, messageid: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$operation  = operation;
    info$messageid = messageid;

	Log::write(LDAP::LOG, info);
	}