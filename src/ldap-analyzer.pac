refine flow LDAP_Flow += {
    function proc_ldap_message(msg: LDAP_PDU) : bool
    %{
        if(msg.operation == "BindRequest"){
            zeek::BifEvent::enqueue_ldap_bind_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "BindResponse"){
            zeek::BifEvent::enqueue_ldap_bind_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "UnbindRequest"){
            zeek::BifEvent::enqueue_ldap_unbind_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "SearchRequest"){
            zeek::BifEvent::enqueue_ldap_search_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "SearchResultEntry"){
            zeek::BifEvent::enqueue_ldap_search_result_entry(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "SearchResultDone"){
            zeek::BifEvent::enqueue_ldap_search_result_done(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ModifyRequest"){
            zeek::BifEvent::enqueue_ldap_modify_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ModifyResponse"){
            zeek::BifEvent::enqueue_ldap_modify_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "AddRequest"){
            zeek::BifEvent::enqueue_ldap_add_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "AddResponse"){
            zeek::BifEvent::enqueue_ldap_add_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "DelRequest"){
            zeek::BifEvent::enqueue_ldap_delete_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "DelResponse"){
            zeek::BifEvent::enqueue_ldap_delete_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ModifyDNRequest"){
            zeek::BifEvent::enqueue_ldap_modify_DN_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ModifyDNResponse"){
            zeek::BifEvent::enqueue_ldap_modify_DN_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }       
        if(msg.operation == "CompareRequest"){
            zeek::BifEvent::enqueue_ldap_compare_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "CompareResponse"){
            zeek::BifEvent::enqueue_ldap_compare_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "AbandonRequest"){
            zeek::BifEvent::enqueue_ldap_abandon_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "SearchResultReference"){
            zeek::BifEvent::enqueue_search_result_refference(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ExtendedRequest"){
            zeek::BifEvent::enqueue_extended_request(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "ExtendedResponse"){
            zeek::BifEvent::enqueue_extended_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }
        if(msg.operation == "IntermediateResponse"){
            zeek::BifEvent::enqueue_intermediate_responce(zeek_analyzer(), zeek_analyzer()->Conn(), ${msg.operation}, ${msg.messageid});
            return true;
        }    
    %}
}

refine typeattr LDAP_PDU += &let{
    proc: bool = $context.flow.proc_ldap_message(this);
}