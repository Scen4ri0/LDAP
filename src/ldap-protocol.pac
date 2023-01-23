type LDAP_PDU(is_orig: bool) = record{
        somedata:       uint32;
        messageID:      uint8;
        opcode:         uint8;
        protocolOp:      ProtocolOp(opcode);
}&let{
        proc1: bool = $context.connection.proc_ldap_bind_request(this);
        proc2: bool = $context.connection.proc_ldap_bind_responce(this);
        proc3: bool = $context.connection.proc_ldap_unbind_request(this);
        proc4: bool = $context.connection.proc_ldap_search_request(this);
        proc5: bool = $context.connection.proc_ldap_search_result_done(this);
}&byteorder=littleendian;

type ProtocolOp(appliaction:    uint8) = case appliaction of{
        0x60   ->  protocolOp1:   BindRequest;
        0x61   ->  protocolOp2:   BindResponse;
        0x42   ->  protocolOp3:   UnbindRequest;
        0x63   ->  protocolOp4:   SearchRequest;
        0x65   ->  protocolOp5:   SearchResultDone;
        default -> data : bytestring &restofdata;
 }&byteorder=littleendian;
       

type BindRequest = record {
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        version:        uint8;
        data :          bytestring &restofdata;
}&byteorder=littleendian;

type BindResponse = record {
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        resultCode:     uint8;
        data :          bytestring &restofdata;
}&byteorder=littleendian;

type UnbindRequest = record{
        data :          bytestring &restofdata;
}&byteorder=littleendian;

type SearchRequest = record{
        somedata1:       uint32;
        somedata2:       uint8;
        scope:          uint8;
        somedata3:       uint16;
        derefAliases:   uint8 ;
        somedata4:       uint16;
        sizeLimit:      uint8;
        somedata5:       uint16;
        timeLimit:      uint8;
        somedata6:       uint16;
        typesOnly:      uint8;
        data :          bytestring &restofdata;
}&byteorder=littleendian;


type SearchResultDone = record{
        somedata1:       uint8;
        somedata2:       uint8;
        somedata3:       uint8;
        resultCode:     uint8;
        data :          bytestring &restofdata;
}&byteorder=littleendian;


