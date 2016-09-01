rule CVE_2015_5667
{
	meta:
		component_name = "HTML-Scrubber module for Perl"
		component_version = "1.14 and earlier"
		custom_title = "Cross-site scripting (XSS) vulnerability in the HTML-Scrubber module before 0.15 for Perl"
		custom_level = "Medium"
		custom_description = "<p>Cross-site scripting (XSS) vulnerability in the HTML-Scrubber module before 0.15 for Perl, when the comment feature is enabled, allows remote attackers to inject arbitrary web script or HTML via a crafted comment.</p>"
	strings:
		$v_0_14 = /our\s+\$VERSION\s*=\s*\'0.14\';/
		$v_0_13 = /our\s+\$VERSION\s*=\s*\'0.13\';/
		$v_0_12 = /our\s+\$VERSION\s*=\s*\'0.12\';/
		$v_0_11 = /our\s+\$VERSION\s*=\s*\'0.11\';/
		$v_0_10 = /our\s+\$VERSION\s*=\s*\'0.10\';/
		$v_0_09 = /\$HTML::Scrubber::VERSION\s*=\s*\'0.09\';/

	condition:
		PerlHTMLScrubberModule and any of ($v*)
}
