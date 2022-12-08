type LDAP_PDU(is_orig: bool) = record{
    messageID:       uint16;
    potocolOp:       PrOp;
}

type PrOp(application: uint16) = record{
     protocolOp: ProtocolOp(appliaction);
}
type ProtocolOp(appliaction: uint16) = case appliaction of{
        0   ->  protocolOp:   BindRequest;
        1   ->  protocolOp:   BindResponse;
        2   ->  protocolOp:   UnbindRequest;
        3   ->  protocolOp:   SearchRequest;
        4   ->  protocolOp:   SearchResultEntry;
        5   ->  protocolOp:   SearchResultDone;
        19  ->  protocolOp:   SearchResultReference;
        6   ->  protocolOp:   ModifyRequest;
        7   ->  protocolOp:   ModifyResponse;
        8   ->  protocolOp:   AddRequest;
        9   ->  protocolOp:   AddResponse;
        10  ->  protocolOp:   DelRequest;
        11  ->  protocolOp:   DelResponse;
        12  ->  protocolOp:   ModifyDNRequest;
        13  ->  protocolOp:   ModifyDNResponse;
        14  ->  protocolOp:   CompareRequest;
        15  ->  protocolOp:   CompareResponse;
        16  ->  protocolOp:   AbandonRequest;
        23  ->  protocolOp:   ExtendedRequest;
        24  ->  protocolOp:   ExtendedResponse;
        25  ->  protocolOp:   IntermediateResponse;
 }


type AttributeValueAssertion = record{
        attributeDesc   LDAP_string(false,1);
        assertionValue  LDAP_string(false,1);
}


type PartialAttribute = record{
        Type:    LDAP_string(false,1);
        vals:    LDAP_string(false,1);
}
     
type ResultCode(rc: uint16) = case of rc{
        0 -> resultCode:      LDAP_string(false,1) = "success";                      
        1 -> resultCode:      LDAP_string(false,1) = "operationsError";              
        2 -> resultCode:      LDAP_string(false,1) = "protocolError";                
        3 -> resultCode:      LDAP_string(false,1) = "timeLimitExceeded";            
        4 -> resultCode:      LDAP_string(false,1) = "sizeLimitExceeded";            
        5 -> resultCode:      LDAP_string(false,1) = "compareFalse";                 
        6 -> resultCode:      LDAP_string(false,1) = "compareTrue";                  
        7 -> resultCode:      LDAP_string(false,1) = "authMethodNotSupported";       
        8 -> resultCode:      LDAP_string(false,1) = "strongerAuthRequired";         
                       
        10 -> resultCode:     LDAP_string(false,1) = "referral";                     
        11 -> resultCode:     LDAP_string(false,1) = "adminLimitExceeded";           
        12 -> resultCode:     LDAP_string(false,1) = "unavailableCriticalExtension"; 
        13 -> resultCode:     LDAP_string(false,1) = "confidentialityRequired";     
        14 -> resultCode:     LDAP_string(false,1) = "saslBindInProgress";           
        16 -> resultCode:     LDAP_string(false,1) = "noSuchAttribute";             
        17 -> resultCode:     LDAP_string(false,1) = "undefinedAttributeType";      
        18 -> resultCode:     LDAP_string(false,1) = "inappropriateMatching";       
        19 -> resultCode:     LDAP_string(false,1) = "constraintViolation";         
        20 -> resultCode:     LDAP_string(false,1) = "attributeOrValueExists";      
        21 -> resultCode:     LDAP_string(false,1) = "invalidAttributeSyntax";    
        32 -> resultCode:     LDAP_string(false,1) = "noSuchObject";            
        33 -> resultCode:     LDAP_string(false,1) = "aliasProblem";               
        34 -> resultCode:     LDAP_string(false,1) = "invalidDNSyntax";          
        36 -> resultCode:     LDAP_string(false,1) = "aliasDereferencingProblem";    
        48 -> resultCode:     LDAP_string(false,1) = "inappropriateAuthentication";
        49 -> resultCode:     LDAP_string(false,1) = "invalidCredentials";          
        50 -> resultCode:     LDAP_string(false,1) = "insufficientAccessRights";    
        51 -> resultCode:     LDAP_string(false,1) = "busy";                 
        52 -> resultCode:     LDAP_string(false,1) = "unavailable";               
        53 -> resultCode:     LDAP_string(false,1) = "unwillingToPerform";        
        54 -> resultCode:     LDAP_string(false,1) = "loopDetect";             
        64 -> resultCode:     LDAP_string(false,1) = "namingViolation";          
        65 -> resultCode:     LDAP_string(false,1) = "objectClassViolation";       
        66 -> resultCode:     LDAP_string(false,1) = "notAllowedOnNonLeaf";       
        67 -> resultCode:     LDAP_string(false,1) = "notAllowedOnRDN";          
        68 -> resultCode:     LDAP_string(false,1) = "entryAlreadyExists";         
        69 -> resultCode:     LDAP_string(false,1) = "objectClassModsProhibited";  
        71 -> resultCode:     LDAP_string(false,1) = "affectsMultipleDSAs";        
        80 -> resultCode:     LDAP_string(false,1) = "other";            
}

       

type BindRequest = record {
        version:                 uint32;
        name:                    LDAP_string(false,1);
        authentication:          AuthenticationChoice;
}

type AuthenticationChoice(authentication: uint8) = case authentication of{
            0   ->       simple:   LDAP_string(false,1);
            3   ->       sasl:   SaslCredentials;
}

type    SaslCredentials = record {
             mechanism:       LDAP_string(false,1);
             credentials:     LDAP_string(false,1);
}

type BindResponse(rc: uint16) = record {
             resultCode: ResultCode(rc);
}

type UnbindRequest = record;

type SearchRequest = record{
             baseObject:      LDAP_string(false,1);
             scope:           Scope;
             derefAliases:    DerefAliases ;
             sizeLimit:       uint32;
             timeLimit:       uint32;
             typesOnly:       bool;
             attributes:      LDAP_string(false,1);
              }
             
type Scope(sc: uint8) = case sc of{
                  0 -> scope: LDAP_string(false,1) = "baseObject";
                  1 -> scope: LDAP_string(false,1) = "singleLevel";
                  2 -> scope: LDAP_string(false,1) = "wholeSubtree";
}

type DerefAliases(da: uint8) = case da of {
                  0 ->   derefAliases: LDAP_string(false,1) = "neverDerefAliases";       
                  1 ->   derefAliases: LDAP_string(false,1) = "derefInSearching";        
                  2 ->   derefAliases: LDAP_string(false,1) = "derefFindingBaseObj";     
                  3 ->   derefAliases: LDAP_string(false,1) = "derefAlways";             
}

type SearchResultEntry = record {
             objectName:     LDAP_string;
             attributes:     []PartialAttribute &until($element == 0);
}


type SearchResultReference = record{
          SIZE: LDAP_string(false,1);
}

type SearchResultDone(rc: uint16) = record{
          resultCode: ResultCode(rc);
}

type ModifyRequest(op: uint8) = record {
             object:         LDAP_string(false,1)
             changes:        Change(op);
}
type Change(op: uint8) = record {
          operation:      Operation(op) 
          modification:    PartialAttribute }

type Oeration(op: uint8) = case op of{
          0 -> operation: LDAP_String(false,1) = "add";     
          1 -> operation: LDAP_String(false,1) = "delete";  
          2 -> operation: LDAP_String(false,1) = "replace";
}

type ModifyResponse(rc: uint16) = record{
          resultCode: ResultCode(rc);
}


type AddRequest = record {
             entry:           LDAP_string(false,1);
             attributes:      [] PartialAttribute &until($element == 0);
}

type AddResponse(rc: uint16) = record{
          resultCode: ResultCode(rc);
}

type DelRequest = record{
          ldapdn: LDAP_string(false,1);
}
     
type DelResponse(rc: uint16) = record{
          resultCode: ResultCode(rc);
}

type ModifyDNRequest = record {
             entry:           LDAP_string(false,1);
             newrdn:          LDAP_String(false,1);
             deleteoldrdn:    bool;
}

type ModifyDNResponse(rc: uint16) = record{
          resultCode: ResultCode(rc);
}

type CompareRequest = record {
             entry:           LDAP_string(false,1);
             ava:             AttributeValueAssertion;
}

type CompareResponse(rc: uint16) = record{
          resultCode: ResultCode(rc);
}

type AbandonRequest = record;
