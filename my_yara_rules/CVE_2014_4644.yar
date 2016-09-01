rule CVE_2014_4644
{
	meta:
		component_name = "Superlinks plugin for Cacti"
		component_version = "1.4-2"
		custom_title = "SQL injection vulnerability in the superlinks plugin 1.4-2 for Cacti"
		custom_level = "Medium"
		custom_description = "<p>SQL injection vulnerability in superlinks.php in the superlinks plugin 1.4-2 for Cacti allows remote attackers to execute arbitrary SQL commands via the id parameter.</p>"
	strings:
		$v_1_4 = /\'version\'\s*=>\s*\'1.4\'/
	condition:
		php_file and CactiSuperlinksPlugin and any of ($v*)
}
