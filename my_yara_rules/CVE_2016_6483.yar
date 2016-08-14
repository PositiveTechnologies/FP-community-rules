rule CVE_2016_6483
{
	meta:
			component_name = "vBulletin"
            component_version = "5.2.0, 5.2.1 or 5.2.2"
            custom_title = "CVE-2016-6483 vBulletin <= 5.2.2 Preauth Server Side Request Forgery (SSRF)"
            custom_level = "High" // High, Medium, Low
            custom_description = "<p>vBulletin software is affected by a SSRF vulnerability that allows unauthenticated remote attackers to access internal services (such as mail servers, memcached, couchDB, zabbix etc.) running on the server hosting vBulletin as well as services on other servers on the local network that are accessible from the target.</p><p>The following versions are affected:</p><ul><li>vBulletin  <= 5.2.2</li><li>vBulletin  <= 4.2.3</li><li>vBulletin  <= 3.8.9</li></ul><p>Please download new version from <a href='http://www.vbulletin.com/'>http://www.vbulletin.com/</a></p>"
	strings:
			$v5_2_0 = /\|\|\s+\#\s+vBulletin\s+5.2.0/
			$v5_2_1 = /\|\|\s+\#\s+vBulletin\s+5.2.1/
			$v5_2_2 = /\|\|\s+\#\s+vBulletin\s+5.2.2/
						
	condition:
			php_file and vBulletin and any of ($v*)
}