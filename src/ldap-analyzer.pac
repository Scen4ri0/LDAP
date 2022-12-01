refine flow LDAP_Flow += {
    function proc_ldap_message(msg: LDAP_PDU) : bool
    %{
        if(msg.protocolOp == "BindRequest"){
            zeek::BifEvent::enqueue_ldap_bind_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "BindResponse"){
            zeek::BifEvent::enqueue_ldap_bind_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "UnbindRequest"){
            zeek::BifEvent::enqueue_ldap_unbind_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "SearchRequest"){
            zeek::BifEvent::enqueue_ldap_search_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "SearchResultEntry"){
            zeek::BifEvent::enqueue_ldap_search_result_entry(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "SearchResultDone"){
            zeek::BifEvent::enqueue_ldap_search_result_done(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ModifyRequest"){
            zeek::BifEvent::enqueue_ldap_modify_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ModifyResponse"){
            zeek::BifEvent::enqueue_ldap_modify_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "AddRequest"){
            zeek::BifEvent::enqueue_ldap_add_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "AddResponse"){
            zeek::BifEvent::enqueue_ldap_add_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "DelRequest"){
            zeek::BifEvent::enqueue_ldap_delete_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "DelResponse"){
            zeek::BifEvent::enqueue_ldap_delete_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ModifyDNRequest"){
            zeek::BifEvent::enqueue_ldap_modify_DN_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ModifyDNResponse"){
            zeek::BifEvent::enqueue_ldap_modify_DN_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }       
        if(msg.protocolOp == "CompareRequest"){
            zeek::BifEvent::enqueue_ldap_compare_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "CompareResponse"){
            zeek::BifEvent::enqueue_ldap_compare_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "AbandonRequest"){
            zeek::BifEvent::enqueue_ldap_abandon_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "SearchResultReference"){
            zeek::BifEvent::enqueue_search_result_refference(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ExtendedRequest"){
            zeek::BifEvent::enqueue_extended_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "ExtendedResponse"){
            zeek::BifEvent::enqueue_extended_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.protocolOp == "IntermediateResponse"){
            zeek::BifEvent::enqueue_intermediate_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }    
    %}
}

refine typeattr LDAP_PDU += &let{
    proc: bool = $context.flow.proc_ldap_message(this);
}