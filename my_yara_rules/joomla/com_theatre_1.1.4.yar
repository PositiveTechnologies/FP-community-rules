rule com_theatre_1_1_4
{
	// @exploit: http://0day.today/exploit/25012
	meta:
			component_name = "com_theatre"
            component_version = "1.1.4"
            custom_title = "Joomla com_threate 1.1.4 SQL injection"
            custom_level = "High" // High, Medium, Low
            custom_description = "<p>SQL injection Vulnerability has been detected in com_theatre component version 1.1.4.</p><p>This component is no longer supported, please stop using it.</p>"
	strings:
			$v1_1_4 = /<version>1.1.4<\/version>/	
	condition:
			xml_file and com_theatre and any of ($v*)
}