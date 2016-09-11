rule CVE_2015_1432
{
	meta:
		component_name = "phpBB forum software"
		component_version = "3.0.12 and below"
		custom_title = "Cross-site request forgery (CSRF) vulnerability in phpBB before 3.0.13"
		custom_level = "Medium"
		custom_description = "<p>The message_options function in includes/ucp/ucp_pm_options.php in phpBB before 3.0.13 does not properly validate the form key, which allows remote attackers to conduct CSRF attacks and change the full folder setting via unspecified vectors.</p>"
	strings:
		$v_3_0_12 = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.12\'\s*\);/
		$v_3_0_11 = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.11\'\s*\);/
		$v_3_0_10 = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.10\'\s*\);/
		$v_3_0_9  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.9\'\s*\);/
		$v_3_0_8  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.8\'\s*\);/
		$v_3_0_7  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.7\'\s*\);/
		$v_3_0_6  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.6\'\s*\);/
		$v_3_0_5  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.5\'\s*\);/
		$v_3_0_4  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.4\'\s*\);/
		$v_3_0_3  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.3\'\s*\);/
		$v_3_0_2  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.2\'\s*\);/
		$v_3_0_1  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.1\'\s*\);/
		$v_3_0_0  = /define\(\s*\'PHPBB_VERSION\'\s*,\s*\'3.0.0\'\s*\);/

	condition:
		php_file and phpBB and any of ($v*)
}
