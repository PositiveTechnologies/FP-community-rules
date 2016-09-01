rule CVE_2015_7686
{
	meta:
		component_name = "Email-Address module for Perl"
		component_version = "1.908 and earlier"
		custom_title = "Algorithmic complexity vulnerability in the Email-Address module 1.908 and earlier for Perl"
		custom_level = "Medium"
		custom_description = "<p>Algorithmic complexity vulnerability in Address.pm in the Email-Address module 1.908 and earlier for Perl allows remote attackers to cause a denial of service (CPU consumption) via a crafted string containing a list of e-mail addresses in conjunction with parenthesis characters that can be associated with nested comments. NOTE: the default configuration in 1.908 mitigates this vulnerability but misparses certain realistic comments.</p>"
	strings:
		$v_1_908 = /\$Email::Address::VERSION\s*=\s*\'1.908\';/
		$v_1_907 = /\$Email::Address::VERSION\s*=\s*\'1.907\';/
		$v_1_906 = /\$Email::Address::VERSION\s*=\s*\'1.906\';/
		$v_1_80  = /\$VERSION\s*=\s*\'1.80\';/
		$v_1_7   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.7\s*\$\)\[1\];/
		$v_1_6   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.6\s*\$\)\[1\];/
		$v_1_5   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.5\s*\$\)\[1\];/
		$v_1_3   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.3\s*\$\)\[1\];/
		$v_1_2   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.2\s*\$\)\[1\];/
		$v_1_1   = /\$VERSION\s*=\s*\(qw\$Revision:\s*1.1\s*\$\)\[1\];/

	condition:
		PerlEmailAddressModule and any of ($v*)
}
