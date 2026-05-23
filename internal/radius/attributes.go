package radius

// Standard attribute type codes (RFC 2865 + RFC 2866 + RFC 2868 + RFC 3162 +
// RFC 3579). Only the ones we actually parse or emit are listed.
const (
	AttrUserName              uint8 = 1   // RFC 2865
	AttrUserPassword          uint8 = 2   // PAP, encrypted
	AttrCHAPPassword          uint8 = 3   // CHAP, 1B CHAP-ID + 16B response
	AttrNASIPAddress          uint8 = 4
	AttrNASPort               uint8 = 5
	AttrServiceType           uint8 = 6
	AttrFramedProtocol        uint8 = 7
	AttrFramedIPAddress       uint8 = 8
	AttrFilterID              uint8 = 11
	AttrFramedMTU             uint8 = 12
	AttrReplyMessage          uint8 = 18
	AttrCallbackNumber        uint8 = 19
	AttrState                 uint8 = 24
	AttrClass                 uint8 = 25
	AttrVendorSpecific        uint8 = 26  // VSA — see vsa.go
	AttrSessionTimeout        uint8 = 27
	AttrIdleTimeout           uint8 = 28
	AttrTerminationAction     uint8 = 29
	AttrCalledStationID       uint8 = 30
	AttrCallingStationID      uint8 = 31
	AttrNASIdentifier         uint8 = 32
	AttrProxyState            uint8 = 33  // proxy chains — echoed verbatim
	AttrAcctStatusType        uint8 = 40
	AttrAcctDelayTime         uint8 = 41
	AttrAcctInputOctets       uint8 = 42
	AttrAcctOutputOctets      uint8 = 43
	AttrAcctSessionID         uint8 = 44
	AttrAcctAuthentic         uint8 = 45
	AttrAcctSessionTime       uint8 = 46
	AttrAcctInputPackets      uint8 = 47
	AttrAcctOutputPackets     uint8 = 48
	AttrAcctTerminateCause    uint8 = 49
	AttrCHAPChallenge         uint8 = 60
	AttrNASPortType           uint8 = 61
	AttrTunnelType            uint8 = 64
	AttrTunnelMediumType      uint8 = 65
	AttrTunnelClientEndpoint  uint8 = 66
	AttrTunnelServerEndpoint  uint8 = 67
	AttrConnectInfo           uint8 = 77
	AttrEAPMessage            uint8 = 79
	AttrMessageAuthenticator  uint8 = 80  // RFC 3579 §3.2
	AttrNASIPv6Address        uint8 = 95
	AttrFramedIPv6Address     uint8 = 168
)

// Service-Type values (RFC 2865 §5.6). Most network OSes accept Admin (6).
const (
	ServiceLogin              uint32 = 1
	ServiceFramed             uint32 = 2
	ServiceCallbackLogin      uint32 = 3
	ServiceCallbackFramed     uint32 = 4
	ServiceOutbound           uint32 = 5
	ServiceAdministrative     uint32 = 6   // <-- admin shell (priv 15)
	ServiceNASPrompt          uint32 = 7   // unprivileged shell (priv 1)
	ServiceAuthenticateOnly   uint32 = 8
	ServiceCallbackNASPrompt  uint32 = 9
	ServiceCallCheck          uint32 = 10
	ServiceCallbackAdmin      uint32 = 11
)

// Acct-Status-Type values (RFC 2866 §5.1).
const (
	AcctStatusStart       uint32 = 1
	AcctStatusStop        uint32 = 2
	AcctStatusInterimUpd  uint32 = 3
	AcctStatusAccountingOn  uint32 = 7
	AcctStatusAccountingOff uint32 = 8
)
