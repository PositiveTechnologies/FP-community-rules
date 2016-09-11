rule CVE_2015_7686
{
	meta:
		component_name = "Email-Address module for Perl"
		component_version = "1.908 and earlier"
		custom_title = "Algorithmic complexity vulnerability in the Email-Address module 1.908 and earlier for Perl"
		custom_level = "Medium"
		custom_description = "<p>Algorithmic complexity vulnerability in Address.pm in the Email-Address module 1.908 and earlier for Perl allows remote attackers to cause a denial of service (CPU consumption) via a crafted string containing a list of e-mail addresses in conjunction with parenthesis characters that can be associated with nested comments. NOTE: the default configuration in 1.908 mitigates this vulnerability but misparses certain realistic comments.</p>"
	strings:
		$v_1_908 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.908(\'|\")\s*;/
		$v_1_907 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.907(\'|\")\s*;/
		$v_1_906 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.906(\'|\")\s*;/
		$v_1_905 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.905(\'|\")\s*;/
		$v_1_904 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.904(\'|\")\s*;/
		$v_1_903 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.903(\'|\")\s*;/
		$v_1_902 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.902(\'|\")\s*;/
		$v_1_901 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.901(\'|\")\s*;/
		$v_1_900 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.900(\'|\")\s*;/
		$v_1_899 = /\$Email::Address::VERSION\s*=\s*(\'|\")1.899(\'|\")\s*;/
		$v_1_898 = /\$VERSION\s*=\s*(\'|\")1.898(\'|\")\s*;/
		$v_1_897 = /\$VERSION\s*=\s*(\'|\")1.897(\'|\")\s*;/
		$v_1_896 = /\$VERSION\s*=\s*(\'|\")1.896(\'|\")\s*;/
		$v_1_895 = /\$VERSION\s*=\s*(\'|\")1.895(\'|\")\s*;/
		$v_1_894 = /\$VERSION\s*=\s*(\'|\")1.894(\'|\")\s*;/
		$v_1_893 = /\$VERSION\s*=\s*(\'|\")1.893(\'|\")\s*;/
		$v_1_892 = /\$VERSION\s*=\s*(\'|\")1.892(\'|\")\s*;/
		$v_1_891 = /our\s+\$VERSION\s*=\s*(\'|\")1.891(\'|\")\s*;/
		$v_1_890 = /our\s+\$VERSION\s*=\s*(\'|\")1.890(\'|\")\s*;/
		$v_1_889 = /\$VERSION\s*=\s*(\'|\")1.889(\'|\")\s*;/
		$v_1_888 = /\$VERSION\s*=\s*(\'|\")1.888(\'|\")\s*;/
		$v_1_887 = /\$VERSION\s*=\s*(\'|\")1.887(\'|\")\s*;/
		$v_1_886 = /\$VERSION\s*=\s*(\'|\")1.886(\'|\")\s*;/
		$v_1_885 = /\$VERSION\s*=\s*(\'|\")1.885(\'|\")\s*;/
		$v_1_884 = /\$VERSION\s*=\s*(\'|\")1.884(\'|\")\s*;/
		$v_1_883 = /\$VERSION\s*=\s*(\'|\")1.883(\'|\")\s*;/
		$v_1_882 = /\$VERSION\s*=\s*(\'|\")1.882(\'|\")\s*;/
		$v_1_881 = /\$VERSION\s*=\s*(\'|\")1.881(\'|\")\s*;/
		$v_1_880 = /\$VERSION\s*=\s*(\'|\")1.880(\'|\")\s*;/
		$v_1_871 = /\$VERSION\s*=\s*(\'|\")1.871(\'|\")\s*;/
		$v_1_870 = /\$VERSION\s*=\s*(\'|\")1.870(\'|\")\s*;/
		$v_1_861 = /\$VERSION\s*=\s*(\'|\")1.861(\'|\")\s*;/
		$v_1_86  = /\$VERSION\s*=\s*(\'|\")1.86(\'|\")\s*;/
		$v_1_85  = /\$VERSION\s*=\s*(\'|\")1.85(\'|\")\s*;/
		$v_1_80  = /\$VERSION\s*=\s*(\'|\")1.80(\'|\")\s*;/
		$v_1_7   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.7\s*\$\)\[1\]\s*;/
		$v_1_6   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.6\s*\$\)\[1\]\s*;/
		$v_1_5   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.5\s*\$\)\[1\]\s*;/
		$v_1_3   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.3\s*\$\)\[1\]\s*;/
		$v_1_2   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.2\s*\$\)\[1\]\s*;/
		$v_1_1   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.1\s*\$\)\[1\]\s*;/
	condition:
		PerlEmailAddressModule and any of ($v*)
}
