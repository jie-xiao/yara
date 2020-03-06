rule crypt_constants_2_lazarus
{
meta:
   Author="NCCIC trusted 3rd party"
   Incident="10135536"
   Date = "2018/04/19"    
   category = "hidden_cobra"
   family = "n/a"
   description = "n/a"
strings:
   $ = {efcdab90}
   $ = {558426fe}
   $ = {7856b4c2}
condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}
rule polarSSL_servernames_lazarus
{
meta:
   Author="NCCIC trusted 3rd party"
   Incident="10135536"
   Date = "2018/04/19"    
   category = "hidden_cobra"
   family = "n/a"
   description = "n/a"
strings:
   $polarSSL = "fjiejffndxklfsdkfjsaadiepwn"
   $sn1 = "www.google.com"
   $sn2 = {77 77 77 2e [1-10] 2e 63 6f 6d}
condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and ($polarSSL and 1 of ($sn*))
}