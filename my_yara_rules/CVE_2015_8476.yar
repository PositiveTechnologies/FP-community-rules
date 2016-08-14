rule CVE_2015_8476
{
	meta:
			component_name = "PHPMailer"
            component_version = "5.2.13 and below"
            custom_title = "CVE-2015-8476 Multiple CRLF injection vulnerabilities in PHPMailer before 5.2.14"
            custom_level = "Medium" // High, Medium, Low
            custom_description = "<p>Multiple CRLF injection vulnerabilities in PHPMailer before 5.2.14 allow attackers to inject arbitrary SMTP commands via CRLF sequences in an (1) email address to the validateAddress function in class.phpmailer.php or (2) SMTP command to the sendCommand function in class.smtp.php.</p><p>Fixed in PHPMailer 5.2.14.</p><p>Please download new version from <a href='https://github.com/PHPMailer/PHPMailer'>https://github.com/PHPMailer/PHPMailer</a></p>"
	strings:
			$v5_2_13 = /public\s+\$Version\s+=\s+(\'|\")5.2.13(\'|\")/
			$v5_2_12 = /public\s+\$Version\s+=\s+(\'|\")5.2.12(\'|\")/
			$v5_2_11 = /public\s+\$Version\s+=\s+(\'|\")5.2.11(\'|\")/
			$v5_2_10 = /public\s+\$Version\s+=\s+(\'|\")5.2.10(\'|\")/
			$v5_2_9  = /public\s+\$Version\s+=\s+(\'|\")5.2.9(\'|\")/
			$v5_2_8  = /public\s+\$Version\s+=\s+(\'|\")5.2.8(\'|\")/
			$v5_2_7  = /public\s+\$Version\s+=\s+(\'|\")5.2.7(\'|\")/
			$v5_2_6  = /public\s+\$Version\s+=\s+(\'|\")5.2.6(\'|\")/
			$v5_2_5  = /public\s+\$Version\s+=\s+(\'|\")5.2.5(\'|\")/
			$v5_2_4  = /public\s+\$Version\s+=\s+(\'|\")5.2.4(\'|\")/
			$v5_1_0  = /public\s+\$Version\s+=\s+(\'|\")5.1(\'|\")/
			$v5_0_2  = /public\s+\$Version\s+=\s+(\'|\")5.0.2(\'|\")/
			$v5_0_0  = /const\s+\VERSION\s+=\s+(\'|\")5.0.0(\'|\")/
			$v2_3 = /public\s+\$Version\s+=\s+(\'|\")2.3(\'|\")/
			$v2_2 = /public\s+\$Version\s+=\s+(\'|\")2.2(\'|\")/
			$v2_0_3 = /public\s+\$Version\s+=\s+(\'|\")2.0.3(\'|\")/

			
	condition:
			php_file and PHPMailer and any of ($v*)
}