rule CVE_2015_3397
{
	meta:
			component_name = "YiiFramework"
            component_version = "2.0.3 and bellow"
            custom_title = "CVE-2015-3397 XSS vulnerability in YiiFramework before 2.0.4"
            custom_level = "Medium"
            custom_description = "<p>Cross-site scripting (XSS) vulnerability in Yii Framework before 2.0.4 allows remote attackers to inject arbitrary web script or HTML via vectors related to JSON, arrays, and Internet Explorer 6 or 7.</p>"
	strings:
			$v2_0_3 = /\s+return\s+(\'|\")2.0.3(\'|\");/
			$v2_0_2 = /\s+return\s+(\'|\")2.0.2(\'|\");/
			$v2_0_1 = /\s+return\s+(\'|\")2.0.1(\'|\");/
			$v2_0_0 = /\s+return\s+(\'|\")2.0.0(\'|\");/
			$v2_0_0_beta = /\s+return\s+(\'|\")2.0.0-beta(\'|\");/
			$v2_0_0_alpha = /\s+return\s+(\'|\")2.0.0-alpha(\'|\");/
	condition:
			php_file and YiiFramework and any of ($v*)
}