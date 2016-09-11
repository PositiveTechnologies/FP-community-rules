rule CVE_2011_2766
{
//This rule was generated by: ./yargen -m FCGI -c CVE-2011-2766
	meta:
		component_name = "FCGI module for Perl"
		component_version = "0.70 through 0.73"
		custom_title = "Sven Verdoolaege FCGI up to 0.73 CGI::Fast unknown vulnerability"
		custom_level = "medium"
		custom_description = "<p>The FCGI (aka Fast CGI) module 0.70 through 0.73 for Perl, as used by CGI::Fast, uses environment variable values from one request during processing of a later request, which allows remote attackers to bypass authentication via crafted HTTP headers.</p>"
	strings:
		$v_0_73 = /our\s+\$VERSION\s*=\s*(\'|\")0.73(\'|\")\s*;/
		$v_0_72 = /our\s+\$VERSION\s*=\s*(\'|\")0.72(\'|\")\s*;/
		$v_0_71 = /our\s+\$VERSION\s*=\s*(\'|\")0.71(\'|\")\s*;/
		$v_0_70 = /our\s+\$VERSION\s*=\s*(\'|\")0.70(\'|\")\s*;/
	condition:
		PerlFCGIModule and any of ($v*)
}