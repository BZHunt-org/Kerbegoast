package lsa



// Définissez les constantes pour les flags Kerberos
const (
	FlagReserved         uint32 = 2147483648
	FlagForwardable      uint32 = 0x40000000
	FlagForwarded        uint32 = 0x20000000
	FlagProxiable        uint32 = 0x10000000
	FlagProxy            uint32 = 0x08000000
	FlagMayPostdate      uint32 = 0x04000000
	FlagPostdated        uint32 = 0x02000000
	FlagInvalid          uint32 = 0x01000000
	FlagRenewable        uint32 = 0x00800000
	FlagInitial          uint32 = 0x00400000
	FlagPreAuthent       uint32 = 0x00200000
	FlagHwAuthent        uint32 = 0x00100000
	FlagOkAsDelegate     uint32 = 0x00040000
	FlagAnonymous        uint32 = 0x00020000
	FlagNameCanonicalize uint32 = 0x00010000
	FlagEncPaRep         uint32 = 0x00010000
	FlagReserved1        uint32 = 0x00000001
	FlagEmpty            uint32 = 0x00000000
)

// Fonction pour convertir les flags en une description textuelle
func DescribeFlagTicket(flags uint32) []string {
	descriptions := []string{}

	if flags&FlagReserved != 0 {
		descriptions = append(descriptions, "Reserved")
	}
	if flags&FlagForwardable != 0 {
		descriptions = append(descriptions, "Forwardable")
	}
	if flags&FlagForwarded != 0 {
		descriptions = append(descriptions, "Forwarded")
	}
	if flags&FlagProxiable != 0 {
		descriptions = append(descriptions, "Proxiable")
	}
	if flags&FlagProxy != 0 {
		descriptions = append(descriptions, "Proxy")
	}
	if flags&FlagMayPostdate != 0 {
		descriptions = append(descriptions, "MayPostdate")
	}
	if flags&FlagPostdated != 0 {
		descriptions = append(descriptions, "Postdated")
	}
	if flags&FlagInvalid != 0 {
		descriptions = append(descriptions, "Invalid")
	}
	if flags&FlagRenewable != 0 {
		descriptions = append(descriptions, "Renewable")
	}
	if flags&FlagInitial != 0 {
		descriptions = append(descriptions, "Initial")
	}
	if flags&FlagPreAuthent != 0 {
		descriptions = append(descriptions, "PreAuthent")
	}
	if flags&FlagHwAuthent != 0 {
		descriptions = append(descriptions, "HwAuthent")
	}
	if flags&FlagOkAsDelegate != 0 {
		descriptions = append(descriptions, "OkAsDelegate")
	}
	if flags&FlagAnonymous != 0 {
		descriptions = append(descriptions, "Anonymous")
	}
	if flags&FlagNameCanonicalize != 0 {
		descriptions = append(descriptions, "NameCanonicalize")
	}
	if flags&FlagEncPaRep != 0 {
		descriptions = append(descriptions, "EncPaRep")
	}
	if flags&FlagReserved1 != 0 {
		descriptions = append(descriptions, "Reserved1")
	}
	if flags&FlagEmpty != 0 {
		descriptions = append(descriptions, "Empty")
	}
	return descriptions
}
