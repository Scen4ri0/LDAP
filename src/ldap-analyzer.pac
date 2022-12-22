refine connection LDAP_Conn += {
    function proc_ldap_bind_request(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_bind_request(zeek_analyzer(), zeek_analyzer()->Conn(),
        ${msg.messageID},
        ${msg.opcode},
        ${msg.protocolOp.protocolOp1.version});
        return true;
    %}
    
    function proc_ldap_bind_responce(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_bind_responce(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode}, 
        ${msg.protocolOp.protocolOp2.resultCode});
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
        ${msg.protocolOp.protocolOp4.scope}, 
        ${msg.protocolOp.protocolOp4.derefAliases}, 
        ${msg.protocolOp.protocolOp4.sizeLimit}, 
        ${msg.protocolOp.protocolOp4.timeLimit}, 
        ${msg.protocolOp.protocolOp4.typesOnly});
        return true;
    %}
        
    function proc_ldap_search_result_done(msg: LDAP_PDU) : bool
    %{
        zeek::BifEvent::enqueue_ldap_search_result_done(zeek_analyzer(), zeek_analyzer()->Conn(), 
        ${msg.messageID}, 
        ${msg.opcode}, 
        ${msg.protocolOp.protocolOp5.resultCode});
        return true;
    %}

}


