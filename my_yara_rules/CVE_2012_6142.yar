rule CVE_2012_6142
{
//This rule was generated by: ./yargen -m HTML::EP -c CVE-2012-6142
	meta:
		component_name = "HTML-EP module for Perl"
		component_version = "0.2011"
		custom_title = "Jochen Wiedmann HTML::EP 0.2011 Session Session::Cookie buffer overflow"
		custom_level = "medium"
		custom_description = "<p>Session::Cookie in the HTML::EP module 0.2011 for Perl does not properly use the Storable::thaw function, which allows remote attackers to execute arbitrary code via a crafted request, which is not properly handled when it is deserialized.</p>"
	strings:
		$v_0_2011  = /\$HTML::EP::VERSION\s*=\s*(\'|\")0.2011(\'|\")\s*;/
	condition:
		PerlHTMLEPModule and any of ($v*)
}
