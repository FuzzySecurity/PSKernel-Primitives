# a-z A-Z 0-9
function Return-AlphaNum {
	param($Maxlen=30)
	$Count = Get-Random -Maximum $Maxlen
	-join ((1..$Count) | %{
		$RandSwitch = $(Get-Random -Maximum 10000)%3
		switch ($RandSwitch) {
			0 {Get-Random -Minimum 48 -Maximum 57}
			1 {Get-Random -Minimum 65 -Maximum 90}
			2 {Get-Random -Minimum 97 -Maximum 122}
		}
	} | % {[char]$_})
}

# Full ASCII
# http://www.asciitable.com/
function Return-FullASCII {
	param($Maxlen=30)
	$Count = Get-Random -Maximum $Maxlen
	-join ((1..$Count) | %{Get-Random -Minimum 0 -Maximum 127} | % {[char]$_})
}

# Random unicode
# http://www.tamasoft.co.jp/en/general-info/unicode-decimal.html
function Return-Unicode {
	param($Maxlen=30)
	$Count = Get-Random -Maximum $Maxlen
	-join ((1..$Count) | %{Get-Random -Minimum 160 -Maximum 65500} | % {[char]$_})
}