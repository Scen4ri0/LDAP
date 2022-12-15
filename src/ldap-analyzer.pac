refine flow LDAP_Flow += {
    function proc_ldap_message(msg: LDAP_PDU) : bool
    %{
        if(msg.protocolOp == 60){
            zeek::BifEvent::enqueue_ldap_bind_request(zeek_analyzer(), zeek_analyzer()->Conn(),
             ${msg.messageid},
             ${msg.protocolOp},
             ${msg.version});
            return true;
        }
        if(msg.protocolOp == 61){
            zeek::BifEvent::enqueue_ldap_bind_responce(zeek_analyzer(), zeek_analyzer()->Conn(), 
            ${msg.messageid}, 
            ${msg.protocolOp}, 
            ${msg.resultCode});
            return true;
        }
        if(msg.protocolOp == 42){
            zeek::BifEvent::enqueue_ldap_unbind_request(zeek_analyzer(), zeek_analyzer()->Conn(), 
            ${msg.messageid}, 
            ${msg.protocolOp});
            return true;
        }
        if(msg.protocolOp == 63){
            zeek::BifEvent::enqueue_ldap_search_request(zeek_analyzer(), zeek_analyzer()->Conn(), 
            ${msg.messageid}, 
            ${msg.protocolOp}, 
            ${msg.scope}, 
            ${msg.derefAliases}, 
            ${msg.sizeLimit}, 
            ${msg.timeLimit}, 
            ${msg.typesOnly});
            return true;
        }
        
        if(msg.protocolOp == 65){
            zeek::BifEvent::enqueue_ldap_search_result_done(zeek_analyzer(), zeek_analyzer()->Conn(), 
            ${msg.messageid}, 
            ${msg.protocolOp}, 
            ${msg.resultCode});
            return true;
        }       
    %}
}

refine typeattr LDAP_PDU += &let{
    proc1: bool = $context.connection.proc_ldap_bind_request(this);
    proc2: bool = $context.connection.proc_ldap_bind_responce(this);
    proc3: bool = $context.connection.proc_ldap_unbind_request(this);
    proc4: bool = $context.connection.proc_ldap_search_request(this);
    proc5: bool = $context.connection.proc_ldap_search_result_done(this);
}