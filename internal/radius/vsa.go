package radius

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Vendor IDs from the IANA "SMI Network Management Private Enterprise Codes"
// registry. We carry only the ones our policy reply path emits.
const (
	VendorCisco     uint32 = 9
	VendorJuniper   uint32 = 2636
	VendorMicrosoft uint32 = 311
	VendorHP        uint32 = 11
	VendorHPE       uint32 = 47196 // newer ArubaOS-CX uses HPE PEN
	VendorAruba     uint32 = 14823
	VendorMikrotik  uint32 = 14988
	VendorPaloAlto  uint32 = 25461
	VendorHuawei    uint32 = 2011
	VendorFortinet  uint32 = 12356
	VendorF5        uint32 = 3375
	VendorCheckPoint uint32 = 2620
)

// Vendor sub-attribute codes we use. Numbers come from each vendor's
// dictionary (see FreeRADIUS dictionaries for the full list).
const (
	// Cisco
	CiscoAVPair      uint8 = 1
	CiscoNASPort     uint8 = 2

	// Juniper
	JuniperLocalUserName  uint8 = 1
	JuniperAllowCommands  uint8 = 2
	JuniperDenyCommands   uint8 = 3
	JuniperAllowConfig    uint8 = 4
	JuniperDenyConfig     uint8 = 5

	// HP / Aruba (ArubaOS-Switch uses HP vendor code, ArubaOS-CX uses HPE).
	HPPrivilegeLevel  uint8 = 1   // value=15 for manager
	ArubaAdminRole    uint8 = 3   // "root", "read-only"
	ArubaUserRole     uint8 = 1
	ArubaUserVlan     uint8 = 2

	// MikroTik
	MikrotikGroup      uint8 = 3   // "full", "read", custom
	MikrotikRateLimit  uint8 = 8

	// Palo Alto
	PaloAltoAdminRole       uint8 = 1
	PaloAltoAdminAccessDomain uint8 = 2

	// Huawei
	HuaweiExecPrivilege uint8 = 29  // 0..15

	// Fortinet
	FortinetGroupName uint8 = 1
	FortinetAccessProfile uint8 = 6

	// F5
	F5LTMUserInfo1 uint8 = 1   // admin profile name e.g. "admin"
	F5LTMUserShell uint8 = 2   // "tmsh", "bash", "none"
	F5LTMUserRole  uint8 = 3   // numeric role code

	// Check Point
	CheckPointUserRole uint8 = 229

	// Microsoft (MS-CHAPv2 / MPPE)
	MSCHAPResponse  uint8 = 1
	MSCHAP2Response uint8 = 25
	MSCHAP2Success  uint8 = 26
	MSCHAPDomain    uint8 = 10
)

// EncodeVSA wraps a vendor sub-attribute in the standard type-26 VSA envelope:
//
//	[VendorID:4][SubType:1][SubLen:1][Value:n]
//
// vendor-length is always at least 2 (sub-type + sub-length).
func EncodeVSA(vendor uint32, subType uint8, value []byte) []byte {
	if len(value) > 249 {
		value = value[:249] // 253 - 4 vendor-id
	}
	out := make([]byte, 4+2+len(value))
	binary.BigEndian.PutUint32(out[0:4], vendor)
	out[4] = subType
	out[5] = uint8(2 + len(value))
	copy(out[6:], value)
	return out
}

// AddVSAString is a convenience wrapper for string-valued VSAs.
func (a *AttributeList) AddVSAString(vendor uint32, subType uint8, value string) {
	a.Add(AttrVendorSpecific, EncodeVSA(vendor, subType, []byte(value)))
}

// AddVSAUint32 encodes a 4-byte integer-valued VSA.
func (a *AttributeList) AddVSAUint32(vendor uint32, subType uint8, value uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	a.Add(AttrVendorSpecific, EncodeVSA(vendor, subType, b[:]))
}

// VendorProfile describes the reply attributes a specific device family expects
// for an admin login. The map is keyed by target.kind (lower-cased) so the
// server can look it up from the NAS-IP → inventory mapping.
type VendorProfile struct {
	// Family is the canonical key ("cisco", "fortinet", …) used in logs.
	Family string
	// FillReply mutates the reply AttributeList in place, adding the VSAs
	// this device family needs. role is the PAM role chosen for the user;
	// privLvl is 1..15 for read-only..admin.
	FillReply func(out *AttributeList, role string, privLvl int)
}

// profileFor returns the vendor profile for a device kind. Unknown kinds fall
// back to a "generic" profile that emits Service-Type=Administrative-User +
// Filter-Id=<role>, which most RADIUS implementations honor.
func profileFor(kind string) VendorProfile {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return genericProfile()
	}
	family := kind
	if i := strings.Index(kind, "-"); i > 0 {
		family = kind[:i]
	}
	switch family {
	case "cisco", "arista", "nxos", "ios", "ios-xe", "iosxe":
		return ciscoProfile()
	case "juniper", "junos":
		return juniperProfile()
	case "hp", "procurve", "hpe", "comware":
		return hpProfile()
	case "aruba", "arubaos":
		return arubaProfile()
	case "mikrotik", "routeros":
		return mikrotikProfile()
	case "paloalto", "palo", "panos", "pan":
		return paloAltoProfile()
	case "huawei", "vrp":
		return huaweiProfile()
	case "fortinet", "fortigate", "forti":
		return fortinetProfile()
	case "f5", "bigip", "ltm":
		return f5Profile()
	case "checkpoint", "cp":
		return checkPointProfile()
	default:
		return genericProfile()
	}
}

func genericProfile() VendorProfile {
	return VendorProfile{
		Family: "generic",
		FillReply: func(out *AttributeList, role string, priv int) {
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			out.AddString(AttrFilterID, role)
		},
	}
}

func ciscoProfile() VendorProfile {
	return VendorProfile{
		Family: "cisco",
		FillReply: func(out *AttributeList, role string, priv int) {
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			if priv <= 0 {
				priv = 1
			}
			out.AddVSAString(VendorCisco, CiscoAVPair, fmt.Sprintf("shell:priv-lvl=%d", priv))
			if role != "" {
				out.AddVSAString(VendorCisco, CiscoAVPair, "shell:roles=\""+role+"\"")
			}
		},
	}
}

func juniperProfile() VendorProfile {
	return VendorProfile{
		Family: "juniper",
		FillReply: func(out *AttributeList, role string, priv int) {
			junosClass := junosClassForRole(role, priv)
			out.AddVSAString(VendorJuniper, JuniperLocalUserName, junosClass)
		},
	}
}

func hpProfile() VendorProfile {
	return VendorProfile{
		Family: "hp",
		FillReply: func(out *AttributeList, role string, priv int) {
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			out.AddVSAUint32(VendorHP, HPPrivilegeLevel, uint32(priv))
		},
	}
}

func arubaProfile() VendorProfile {
	return VendorProfile{
		Family: "aruba",
		FillReply: func(out *AttributeList, role string, priv int) {
			r := arubaRoleForRole(role)
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			out.AddVSAString(VendorAruba, ArubaAdminRole, r)
		},
	}
}

func mikrotikProfile() VendorProfile {
	return VendorProfile{
		Family: "mikrotik",
		FillReply: func(out *AttributeList, role string, priv int) {
			g := mikrotikGroupForRole(role)
			out.AddVSAString(VendorMikrotik, MikrotikGroup, g)
		},
	}
}

func paloAltoProfile() VendorProfile {
	return VendorProfile{
		Family: "paloalto",
		FillReply: func(out *AttributeList, role string, priv int) {
			panRole := paloAltoRoleForRole(role, priv)
			out.AddVSAString(VendorPaloAlto, PaloAltoAdminRole, panRole)
		},
	}
}

func huaweiProfile() VendorProfile {
	return VendorProfile{
		Family: "huawei",
		FillReply: func(out *AttributeList, role string, priv int) {
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			out.AddVSAUint32(VendorHuawei, HuaweiExecPrivilege, uint32(priv))
		},
	}
}

func fortinetProfile() VendorProfile {
	return VendorProfile{
		Family: "fortinet",
		FillReply: func(out *AttributeList, role string, priv int) {
			out.AddUint32(AttrServiceType, ServiceAdministrative)
			out.AddVSAString(VendorFortinet, FortinetGroupName, "PAM-Admins")
			// access_profile is an optional override the FortiGate accepts.
			out.AddVSAString(VendorFortinet, FortinetAccessProfile,
				fortinetProfileForRole(role))
		},
	}
}

func f5Profile() VendorProfile {
	return VendorProfile{
		Family: "f5",
		FillReply: func(out *AttributeList, role string, priv int) {
			role = strings.ToLower(strings.TrimSpace(role))
			info := "admin"
			shell := "tmsh"
			if priv < 15 {
				info = "guest"
				shell = "none"
			}
			if role == "admin" || role == "secops" {
				info = "admin"
			}
			out.AddVSAString(VendorF5, F5LTMUserInfo1, info)
			out.AddVSAString(VendorF5, F5LTMUserShell, shell)
		},
	}
}

func checkPointProfile() VendorProfile {
	return VendorProfile{
		Family: "checkpoint",
		FillReply: func(out *AttributeList, role string, priv int) {
			cpRole := "adminRole"
			if priv < 15 {
				cpRole = "monitorRole"
			}
			out.AddVSAString(VendorCheckPoint, CheckPointUserRole, cpRole)
		},
	}
}

// junosClassForRole maps a PAM role to a JunOS login class. Customer-defined
// classes (operator, super-user, etc.) are common; we ship sane defaults.
func junosClassForRole(role string, priv int) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return "super-user"
	case "netops":
		return "operator"
	case "viewer", "user":
		return "read-only"
	}
	if priv >= 15 {
		return "super-user"
	}
	return "read-only"
}

func arubaRoleForRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return "root"
	case "netops":
		return "network-operations"
	case "viewer", "user":
		return "read-only"
	}
	return "read-only"
}

func mikrotikGroupForRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return "full"
	case "netops":
		return "write"
	case "viewer", "user":
		return "read"
	}
	return "read"
}

func paloAltoRoleForRole(role string, priv int) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return "superuser"
	case "netops":
		return "deviceadmin"
	case "viewer", "user":
		return "auditadmin"
	}
	if priv >= 15 {
		return "superuser"
	}
	return "auditadmin"
}

func fortinetProfileForRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return "super_admin"
	case "netops":
		return "prof_admin"
	case "viewer", "user":
		return "no_access"
	}
	return "prof_admin"
}

// privLevelForRole maps PAM roles to a numeric privilege used by HP/Huawei.
// 15 = full admin, 1 = read-only.
func privLevelForRole(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return 15
	case "netops":
		return 10
	case "viewer", "user":
		return 1
	}
	return 1
}
