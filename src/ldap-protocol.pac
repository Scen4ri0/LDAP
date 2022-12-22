type LDAP_PDU(is_orig: bool) = record{
        somedata:       uint32;
        messageID:      uint8;
        opcode:         uint8;
        protocolOp:      ProtocolOp(opcode);
}

type ProtocolOp(appliaction:    uint8) = case appliaction of{
        0x60   ->  protocolOp1:   BindRequest;
        0x61   ->  protocolOp2:   BindResponse;
        0x42   ->  protocolOp3:   UnbindRequest;
        0x63   ->  protocolOp4:   SearchRequest;
        0x65   ->  protocolOp5:   SearchResultDone;
 }
     
type ResultCode(rc: uint8) = case rc of {
        0x00 -> resultCode1:      uint8;# "success";                         
        0x20 -> resultCode2:      uint8;# "noSuchObject";             
}

       

type BindRequest = record {
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        version:        uint32;
        data :          bytestring &restofdata;
}&let{proc: bool = $context.connection.proc_ldap_bind_request(this);}&byteorder=littleendian;

type BindResponse = record {
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        rc:             uint8;
        resultCode:     ResultCode(rc);
        data :          bytestring &restofdata;
}&let{proc: bool = $context.connection.proc_ldap_bind_responce(this);}&byteorder=littleendian;

type UnbindRequest = record{
        data :          bytestring &restofdata;
}&let{proc: bool = $context.connection.proc_ldap_Unbind_request(this);}&byteorder=littleendian;

type SearchRequest = record{
        somedata1:       uint32;
        somedata2:       uint8;
        sc:             uint8;
        scope:          Scope(sc);
        somedata3:       uint16;
        da:             uint8;
        derefAliases:   DerefAliases(da) ;
        somedata4:       uint16;
        sizeLimit:      uint8;
        somedata5:       uint16;
        timeLimit:      uint8;
        somedata6:       uint16;
        typesOnly:      bool;
        data :          bytestring &restofdata;
}&let{proc: bool = $context.connection.proc_ldap_search_request(this);}&byteorder=littleendian;


type Scope(sc: uint8) = case sc of{
        0x00 -> scope1:        uint8;# "baseObject";
        0x01 -> scope2:        uint8;# = "singleLevel";
        0x02 -> scope3:        uint8;# = "wholeSubtree";
}

type DerefAliases(da: uint8) = case da of {
        0x00 ->   derefAliases1:       uint8;# "neverDerefAliases";       
        0x01 ->   derefAliases2:       uint8;# "derefInSearching";        
        0x02 ->   derefAliases3:       uint8;# "derefFindingBaseObj";     
        0x03 ->   derefAliases4:       uint8;# "derefAlways";             
}

type SearchResultDone = record{
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        rc:             uint8;
        resultCode:     ResultCode(rc);
        data :          bytestring &restofdata;
}&let{proc: bool = $context.connection.proc_ldap_search_result_done(this);}&byteorder=littleendian;


