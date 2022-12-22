refine flow LDAP_Flow += {
    function proc_ldap_bind_request(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_bind_request(zeek_analyzer(), zeek_analyzer()->Conn(),
        ${msg.messageID},
        ${msg.opcode},
        ${msg.version});
        return true;
    %}
    
    function proc_ldap_bind_responce(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_bind_responce(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode}, 
        ${msg.resultCode});
        return true;
    %}

    function proc_ldap_Unbind_request(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_unbind_request(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode});
        return true;
    %}

    function proc_ldap_search_request(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_search_request(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode}, 
        ${msg.scope}, 
        ${msg.derefAliases}, 
        ${msg.sizeLimit}, 
        ${msg.timeLimit}, 
        ${msg.typesOnly});
        return true;
    %}
        
    function proc_ldap_search_result_done(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_search_result_done(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode}, 
        ${msg.resultCode});
        return true;
    %}

}


