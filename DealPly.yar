rule DealPly
{
	strings:
		$a="Yellow"
		$b="Red"
		$c="smartscreen"
		$d="microsoft"
		$e="Authorization"
		$f="webadvisorc"
		$g="default"
	condition:
		4 of them 
}