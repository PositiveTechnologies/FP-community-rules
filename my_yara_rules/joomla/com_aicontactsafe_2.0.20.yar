rule com_aicontactsafe_2_0_20
{
	meta:
			component_name = "com_aicontactsafe"
            component_version = "2.0.20"
            custom_title = "Joomla com_aicontactsafe 2.0.20 Multiple Vulnerabilities"
            custom_level = "High" // High, Medium, Low
            custom_description = "<p>aiContactSafe is An AJAX driven component to place a contact form anywhere on your web page with any number of custom fields of different types, including attachments. Arbitrary File Upload and SQL injection Vulnerability has been detected in version 2.0.21.</p><p>Please download new version from <a href='http://www.algisinfo.com/en/download/category/1-free-extensions.html'>http://www.algisinfo.com/en/download/category/1-free-extensions.html</a></p>"
	strings:
			$v2_0_20 = /<version>2.0.20(.)*\w*<\/version>/	
	condition:
			xml_file and com_aicontactsafe and any of ($v*)
}