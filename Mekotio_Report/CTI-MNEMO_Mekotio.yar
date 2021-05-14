import "pe"

rule Mekotio_MSI_Detection {
	meta:
		author = "Mnemo Cyber Threat Intelligence"
		description = "Rule for detect MSI samples of Mekotio"
		notes = "This rule detect variants of Mekotio with the vhash: 6fd8b4e40c1df80d7cbde4b303d6e264 and 266140c755069fc1ae0272fda3c4ea0b"
		TLP = "White"
		
	strings:
		$s1 = "AI_FileDownload" ascii
		$s2 = "Error en el servidor FDIArchivo de clave" ascii
		$s3 = { 73 75 62 73 74 72 } // string: substr in JavaScript
		$s4 = { 00 4C 00 45 00 43 00 54 00 20 00 60 00 54 00 65 00 78 00 74 00 60 00 20 00 46 00 52 00 4F 00 4D } // LECT `Text` FROM

	condition:
		uint32(0) == 0xE011CFD0 // MSI
		and all of them
}