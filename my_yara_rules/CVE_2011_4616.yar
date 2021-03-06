rule CVE_2011_4616
{
//This rule was generated by: ./yargen -m HTML::Template::Pro -c CVE-2011-4616
	meta:
		component_name = "HTML-Template-Pro module for Perl"
		component_version = "before 0.9507"
		custom_title = "Igor Vlasenko HTML-Template-Pro up to 0.9506 cross site scripting"
		custom_level = "low"
		custom_description = "<p>Cross-site scripting (XSS) vulnerability in the HTML-Template-Pro module before 0.9507 for Perl allows remote attackers to inject arbitrary web script or HTML via template parameters, related to improper handling of (greater than) and (less than) characters.</p>"
	strings:
		$v_0_9506 = /\$VERSION\s*=\s*(\'|\")0.9506(\'|\")\s*;/
		$v_0_9505 = /\$VERSION\s*=\s*(\'|\")0.9505(\'|\")\s*;/
		$v_0_9504 = /\$VERSION\s*=\s*(\'|\")0.9504(\'|\")\s*;/
		$v_0_9503 = /\$VERSION\s*=\s*(\'|\")0.9503(\'|\")\s*;/
		$v_0_9502 = /\$VERSION\s*=\s*(\'|\")0.9502(\'|\")\s*;/
		$v_0_9501 = /\$VERSION\s*=\s*(\'|\")0.9501(\'|\")\s*;/
		$v_0_95   = /\$VERSION\s*=\s*(\'|\")0.95(\'|\")\s*;/
		$v_0_94   = /\$VERSION\s*=\s*(\'|\")0.94(\'|\")\s*;/
		$v_0_93   = /\$VERSION\s*=\s*(\'|\")0.93(\'|\")\s*;/
		$v_0_92   = /\$VERSION\s*=\s*(\'|\")0.92(\'|\")\s*;/
		$v_0_91   = /\$VERSION\s*=\s*(\'|\")0.91(\'|\")\s*;/
		$v_0_90   = /\$VERSION\s*=\s*(\'|\")0.90(\'|\")\s*;/
		$v_0_87   = /\$VERSION\s*=\s*(\'|\")0.87(\'|\")\s*;/
		$v_0_86   = /\$VERSION\s*=\s*(\'|\")0.86(\'|\")\s*;/
		$v_0_85   = /\$VERSION\s*=\s*(\'|\")0.85(\'|\")\s*;/
		$v_0_84   = /\$VERSION\s*=\s*(\'|\")0.84(\'|\")\s*;/
		$v_0_83   = /\$VERSION\s*=\s*(\'|\")0.83(\'|\")\s*;/
		$v_0_82   = /\$VERSION\s*=\s*(\'|\")0.82(\'|\")\s*;/
		$v_0_81   = /\$VERSION\s*=\s*(\'|\")0.81(\'|\")\s*;/
		$v_0_80   = /\$VERSION\s*=\s*(\'|\")0.80(\'|\")\s*;/
		$v_0_76   = /\$VERSION\s*=\s*(\'|\")0.76(\'|\")\s*;/
		$v_0_75   = /\$VERSION\s*=\s*(\'|\")0.75(\'|\")\s*;/
		$v_0_74   = /\$VERSION\s*=\s*(\'|\")0.74(\'|\")\s*;/
		$v_0_73   = /\$VERSION\s*=\s*(\'|\")0.73(\'|\")\s*;/
		$v_0_72   = /\$VERSION\s*=\s*(\'|\")0.72(\'|\")\s*;/
		$v_0_71   = /\$VERSION\s*=\s*(\'|\")0.71(\'|\")\s*;/
		$v_0_70   = /\$VERSION\s*=\s*(\'|\")0.70(\'|\")\s*;/
		$v_0_69   = /\$VERSION\s*=\s*(\'|\")0.69(\'|\")\s*;/
		$v_0_68   = /\$VERSION\s*=\s*(\'|\")0.68(\'|\")\s*;/
		$v_0_67   = /\$VERSION\s*=\s*(\'|\")0.67(\'|\")\s*;/
		$v_0_66   = /\$VERSION\s*=\s*(\'|\")0.66(\'|\")\s*;/
		$v_0_65   = /\$VERSION\s*=\s*(\'|\")0.65(\'|\")\s*;/
		$v_0_64   = /\$VERSION\s*=\s*(\'|\")0.64(\'|\")\s*;/
		$v_0_62   = /\$VERSION\s*=\s*(\'|\")0.62(\'|\")\s*;/
		$v_0_61   = /\$VERSION\s*=\s*(\'|\")0.61(\'|\")\s*;/
		$v_0_60   = /\$VERSION\s*=\s*(\'|\")0.60(\'|\")\s*;/
		$v_0_59   = /\$VERSION\s*=\s*(\'|\")0.59(\'|\")\s*;/
		$v_0_58   = /\$VERSION\s*=\s*(\'|\")0.58(\'|\")\s*;/
		$v_0_57   = /\$VERSION\s*=\s*(\'|\")0.57(\'|\")\s*;/
		$v_0_56   = /\$VERSION\s*=\s*(\'|\")0.56(\'|\")\s*;/
		$v_0_55   = /\$VERSION\s*=\s*(\'|\")0.55(\'|\")\s*;/
		$v_0_54   = /\$VERSION\s*=\s*(\'|\")0.54(\'|\")\s*;/
		$v_0_53   = /\$VERSION\s*=\s*(\'|\")0.53(\'|\")\s*;/
		$v_0_52   = /\$VERSION\s*=\s*(\'|\")0.52(\'|\")\s*;/
		$v_0_50   = /\$VERSION\s*=\s*(\'|\")0.50(\'|\")\s*;/
		$v_0_48   = /\$VERSION\s*=\s*(\'|\")0.48(\'|\")\s*;/
		$v_0_46   = /\$VERSION\s*=\s*(\'|\")0.46(\'|\")\s*;/
		$v_0_45   = /\$VERSION\s*=\s*(\'|\")0.45(\'|\")\s*;/
		$v_0_44   = /\$VERSION\s*=\s*(\'|\")0.44(\'|\")\s*;/
		$v_0_43   = /\$VERSION\s*=\s*(\'|\")0.43(\'|\")\s*;/
		$v_0_42   = /\$VERSION\s*=\s*(\'|\")0.42(\'|\")\s*;/
		$v_0_41   = /\$VERSION\s*=\s*(\'|\")0.41(\'|\")\s*;/
		$v_0_40   = /\$VERSION\s*=\s*(\'|\")0.40(\'|\")\s*;/
	condition:
		PerlHTMLTemplateProModule and any of ($v*)
}
