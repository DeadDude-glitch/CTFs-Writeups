At time it was the last 30 minutes before the CTF competition ends,  and we were 200 points away from the first place and all the info I was able to gather is that the dropper used pastebin to download the actual malware on [United State Naval Academy Report](https://www.usna.edu/CyberCenter/_files/documents/Operation-Blockbuster-Report.pdf).

Challenge description mentions an Advanced Persistent Threat (APT) [Lazarus Group](https://en.wikipedia.org/wiki/Lazarus_Group) specifically their [[Operation Troy]] malware in 2014, detailing that the group has published a document that contains sensitive information that gave them away then later a hint was published saying that only after finding the documents and malware source code the investigator shall find the flag.

I was clueless regarding finding the malware source code and documents, but thats where having a great team comes to play as [Mohammd Gabr](https://www.linkedin.com/in/mohammed-g-aa58b110a/) came in and saved the day by mentioning vx-underground.

Thanks to vx-underground highly organized files we were able to find the needed document and source code [here](https://www.vx-underground.org/#E:/root/APTs/2013/2013.03.20%20-%20Operation%20Troy). 

Of course there is no way we were able to read the entire document given that the remaining time was not much hence we searched with key words as `password` and `pastebin` for a lead and it did not disappoint!

* **on page 4**
```
Hi, Dear Friends, We are very happy to inform you the following news. We, NewRomanic Cyber Army Team, verified our #OPFuckKorea2003. We have now a great deal of personal information in our hands. Those includes; 2.49M of _ member table data, cms_info more than 50M from . Much information from Bank. We destroyed more than 0.18M of PCs. Many auth Hope you are lucky. 11th, 12th, 13th, 21st, 23rd and 27th HASTATI Detachment. Part of PRINCIPES Elements. p.s For more information, please visit www.dropbox.com login with joseph.r.ulatoski@gmail.com::lqaz@WSX3edc$RFV. Please also visit pastebin.com.
```

* **on page 23**
```
The files to be sent to the attacker’s server are zipped using the open-source Zip Utils.6 The component uses the password dkwero38oerA^t@#. We have consistently found this password in the malware dating back to 2009. It is used primarily to archive items to be stolen from infected systems.
```
first thing comes to mind when you have a username is sherlock OSINT tool, and we used exactly that.
`https://bitcoinforum.com/profile/joseph.r.ulatoski`

Following this link you should find that the user was created recently and not very active which matches the attributes a typical one time CTF. Not only that but also it has 1 post.

```
Hello Guys, I need help to start mining but before we go for this can you check my data on pastebin?  
  
pastebin.com/wkxJmxnW  
  
hope you feel great now
```

FINALY THE LINK WE WERE SEARCHING FOR!!!

the link required a password but we already have those from the document since as a digital forensics investigator you naturally acquire the habit of keeping important info in an open notepad just in case you need them later.

the password was `dkwero38oerA^t@#.` and we got the flag in the last 10 minutes.
`Flag{FR13ND5_R41lY1NG_3VERY0N3_EMBR4C1N9_P34CE_4DV0C473_L0U61Y_3XPRE551N9_S01iDAR17Y}`




