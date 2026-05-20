package saml

import (
	"encoding/xml"

	"github.com/crewjam/saml"
)

// samlMetadataXML marshals an EntityDescriptor to XML. crewjam already
// implements MarshalXML on the type; this thin wrapper exists so the rest of
// the package doesn't have to deal with the xml import.
func samlMetadataXML(md *saml.EntityDescriptor) ([]byte, error) {
	return xml.MarshalIndent(md, "", "  ")
}
