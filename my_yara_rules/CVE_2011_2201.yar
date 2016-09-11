rule CVE_2011_2201
{
//This rule was generated by: ./yargen -m Data::FormValidator -c CVE-2011-2201
	meta:
		component_name = "Data-FormValidator module for Perl"
		component_version = "4.66 and earlier"
		custom_title = "Mark Stosberg Data::FormValidator before 4.67 unknown vulnerability"
		custom_level = "low"
		custom_description = "<p>The Data::FormValidator module 4.66 and earlier for Perl, when untaint_all_constraints is enabled, does not properly preserve the taint attribute of data, which might allow remote attackers to bypass the taint protection mechanism via form input.</p>"
	strings:
		$v_4_66    = /\$VERSION\s*=\s*(\'|\")4.66(\'|\")\s*;/
		$v_4_65    = /\$VERSION\s*=\s*(\'|\")4.65(\'|\")\s*;/
		$v_4_63    = /\$VERSION\s*=\s*(\'|\")4.63(\'|\")\s*;/
		$v_4_62    = /\$VERSION\s*=\s*(\'|\")4.62(\'|\")\s*;/
		$v_4_61    = /\$VERSION\s*=\s*(\'|\")4.61(\'|\")\s*;/
		$v_4_60    = /\$VERSION\s*=\s*(\'|\")4.60(\'|\")\s*;/
		$v_4_57    = /\$VERSION\s*=\s*(\'|\")4.57(\'|\")\s*;/
		$v_4_56    = /\$VERSION\s*=\s*(\'|\")4.56(\'|\")\s*;/
		$v_4_55    = /\$VERSION\s*=\s*(\'|\")4.55(\'|\")\s*;/
		$v_4_54    = /\$VERSION\s*=\s*(\'|\")4.54(\'|\")\s*;/
		$v_4_52    = /\$VERSION\s*=\s*(\'|\")4.52(\'|\")\s*;/
		$v_4_51    = /\$VERSION\s*=\s*(\'|\")4.51(\'|\")\s*;/
		$v_4_50    = /\$VERSION\s*=\s*(\'|\")4.50(\'|\")\s*;/
		$v_4_49_1  = /\$VERSION\s*=\s*(\'|\")4.49_1(\'|\")\s*;/
		$v_4_40    = /\$VERSION\s*=\s*(\'|\")4.40(\'|\")\s*;/
		$v_4_30    = /\$VERSION\s*=\s*(\'|\")4.30(\'|\")\s*;/
		$v_4_21_01 = /\$VERSION\s*=\s*(\'|\")4.21_01(\'|\")\s*;/
		$v_4_20    = /\$VERSION\s*=\s*(\'|\")4.20(\'|\")\s*;/
		$v_4_14    = /\$VERSION\s*=\s*(\'|\")4.14(\'|\")\s*;/
		$v_4_13    = /\$VERSION\s*=\s*(\'|\")4.13(\'|\")\s*;/
		$v_4_12    = /\$VERSION\s*=\s*(\'|\")4.12(\'|\")\s*;/
		$v_4_11    = /\$VERSION\s*=\s*(\'|\")4.11(\'|\")\s*;/
		$v_4_10    = /\$VERSION\s*=\s*(\'|\")4.10(\'|\")\s*;/
		$v_4_02    = /\$VERSION\s*=\s*(\'|\")4.02(\'|\")\s*;/
		$v_4_01    = /\$VERSION\s*=\s*(\'|\")4.01(\'|\")\s*;/
		$v_4_00_02 = /\$VERSION\s*=\s*(\'|\")4.00_02(\'|\")\s*;/
		$v_4_00_01 = /\$VERSION\s*=\s*(\'|\")4.00_01(\'|\")\s*;/
		$v_4_00    = /\$VERSION\s*=\s*(\'|\")4.00(\'|\")\s*;/
	condition:
		PerlDataFormValidatorModule and any of ($v*)
}