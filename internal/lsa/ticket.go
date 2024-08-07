package lsa



import (
	"github.com/Serizao/GoRottenTomato/asn1"
	"github.com/Serizao/GoRottenTomato/krb5/flags"
	)

var ticketFlagsMap = map[int]string{
	flags.Reserved               :  "reserved",
	flags.Forwardable            :  "forwardable",
	flags.Forwarded              :  "forwarded",
	flags.Proxiable              :  "proxiable",
	flags.Proxy                  :  "proxy",
	flags.Allow_Postdate         :  "allow-postdate",
	flags.Postdated              :  "postdated",
	flags.Invalid                :  "invalid",
	flags.Renewable              :  "renewable",
	flags.Initial                :  "initial",
	flags.PreAuthent             :  "pre-authent",
	flags.HwAuthent              :  "hwauthent",
	flags.TransitedPolicyChecked :  "transited-policy-checked",
	flags.OkAsDelegate           :  "ok-as-delegate",
	flags.CONSTRAINED_DELEGATION :  "DELEGATION",
	flags.NameCanonicalize       :  "name-canonicalize",
}

func DisplayTickets(ticketsFlags asn1.BitString) []string {
	flag := make([]string, 0)
	for i := flags.Reserved; i <= flags.NameCanonicalize; i++ {
		if ticketsFlags.At(i) == 1 {
			flag = append(flag, ticketFlagsMap[i])
		}
	}
	return flag
}