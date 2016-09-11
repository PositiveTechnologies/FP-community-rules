rule CVE_2016_4069
{
	meta:
		component_name = "Roundcube Webmail"
		component_version = "1.1.4 and below"
		custom_title = "Cross-site request forgery (CSRF) vulnerability in Roundcube Webmail before 1.1.5"
		custom_level = "Medium"
		custom_description = "<p>Cross-site request forgery (CSRF) vulnerability in Roundcube Webmail before 1.1.5 allows remote attackers to hijack the authentication of users for requests that download attachments and cause a denial of service (disk consumption) via unspecified vectors.</p>"
	strings:
		$v1_1_4 = /Version\s+1.1.4\W/
		$v1_1_3 = /Version\s+1.1.3\W/
		$v1_1_2 = /Version\s+1.1.2\W/
		$v1_1_1 = /Version\s+1.1.1\W/
		$v1_1_0 = /Version\s+1.1.0\W/
	condition:
		php_file and RoundCubeWebmail and any of ($v*)
}
