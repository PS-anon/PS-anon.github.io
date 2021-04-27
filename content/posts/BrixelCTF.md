---
featured_image: "logo.jpg"
title : Brixel CTF
published : true
date: 2020-12-31T12:59:05+02:00
author : PS
draft: true
---


## Contents

- Lottery Ticket (forensics)

- Lost evidence (forensics)

- Dadjokes (web)

- PathFinder 1,2 (web)

- Android app (reverse)

- Punchcard (old tech)

- Goodbye old friend (old tech)

- The tape (old tech)

- Doc-deception (steg)

- Limewire audio (steg)

- Conclusions



### Lottery Ticket  
*Description* :
	Someone is trying to sell this lottery ticket online, it has the winning numbers but I suspect foul play. Can you tell me which the new numbers are that are photoshopped? Add them all up, the resulting number is the flag   


![test](lot1.png)

Since  it is forensics , I straight up went  to http://fotoforensics.com/  
I applied the ELA filter and : 



![test](lot2.png)

Adding the highlighted numbers up we get the flag  
{{< highlight go >}} Flag Proof : brixelCTF{203}{{< / highlight >}}  


### Lost Evidence
*Description* :
A buddy of mine is in serious trouble. He works for the feds and accidentally deleted a pendrive containing crucial evidence

Can you get it back and tell us what the evidence is?

We need to know what the suspect bought

*Solve* :

We get an .img file, which after using recuva we get 2 .wav files. Then after listening we hear a tapped phone convo , well this is where my happiness ended.  
I used <https://github.com/fabzzap/audiotap> to get the keys pressed from the .wav then seaching online for a photo of old phone keyborad I manually decoded the message  

![test](los1.png)
{{< highlight go >}}  Message : THX FOR THE COCAINE BRUH {{< / highlight >}}  
{{< highlight go >}}  Flag Proof :  brixelCTF{cocaine} {{< / highlight >}}  


### DadJokes
*Description* :  
Darn! Some idiot scriptkiddy broke my favorite website full of dad jokes!

I can't seem to contact the owner to fix the site

Can you bring it back and remove the defaced page?  

*Solve* :
So, opening the web site link we get :

![test](dad1.png)
Looking at the source code I saw an interesting comment :

{{< highlight go >}}  <!-- Hey bozo! I left your original index file under index_backup.html so you can see how your site looked before I used my l33t skillz to deface it. -->  {{< / highlight >}}  
Going at index_backup.html we get the website that we have to put back onto the first page

![test](dad2.png)
We see an submit button which instantly catches my attention 
![test](dad3.png)
We have our way in !
Playing around that field I realised it is vuln to XSS  
When coping the source code of the backup and pasting it there , well , the page works  
Now we need a way to overwrite the index file , hmmm..
Then an idea came , what  if the page is vuln to LFI too  
When I looked at the url I realised that I am right :

![test](dad4.png)
After doing some changes :
![test](dad5.png)
We get a response :
![test](dad6.png)
Hmmmmmmmm  
The final payload : 
![test](dad7.png)
Replace the content with the source code of the backup and DONE we get the flag  
{{< highlight go >}}   Flag Proof :  brixelCTF{lamejoke} {{< / highlight >}}

### PathFinder 1
These f*cking religious sects!
These guys brainwashed my niece into their demeted world of i-readings and other such nonsense.  

The feds recently closed their churches, but it seems they are preparing for a new online platform to continue their malicious activities.  

can you gain access to their admin panel to shut them down?  
*Solve* :
Imo this was the best chall of all :D  
Website :  

![test](path1.png)
My attention  was instantly attracted by the url : 
{{< highlight go >}}   Flag Proof : pathfinder/index.php?page=home.php {{< / highlight >}}  
Yup, I instantly knew it is LFI  
It also has an admin page which requires username/passwd so it was clear that the goal is to get the password  
Now, I remembered about htpasswd and the payload was :
{{< highlight go >}}  /pathfinder/index.php?page=admin/.htpasswd {{< / highlight >}}  
And we got the flag :  
{{< highlight go >}}  Flag proof : brixelCTF{unsafe_include} {{< / highlight >}}  

### PathFinder 2
It seems they updated their security. can you get the password for their admin section on their new site?  

oh yeah, let's assume they are running a php version below 5.3.4 here...  
*Solve* :
So, it is the same website with improved security  
BUUUUTTTT WE GOT A HUUUUGEEEE HINT  
*below 5.3.4 here...*  
So with the help of google I found that null byte injection was present in php versions below 5.3.4  
Well I just tried a few payloads and I got the flag  
{{< highlight go >}}  Payload /pathfinder2/index.php?page=admin/.htpasswd%00.php {{< / highlight >}}  
{{< highlight go >}}  Flag proof : brixelCTF{outdated_php} {{< / highlight >}}  


### Android app
One of my team mates done this one :D thx Kayn  
*Description*
This little android app requires a password, can you find it?  

the flag is the password  

*Solve* :  
So, you just decompile the apk and run 
{{< highlight go >}}  grep -Rina 'brixelCTF{'{{< / highlight >}}

### punchcard  
I found this old punchcard

it seems to be classified

can you figure out what's on there?

*Solve* :
You get a png and you go to <https://www.masswerk.at/cardreader/> and that's all !  

![test](pc1.png)
![test](pc2.png)
{{< highlight go >}}  THE FLAG IS BRIXELCTF(M41NFR4M3) {{< / highlight >}}




### Goodbye old friend
*Description*
On 31/12/2020 support for flash will end

Therefor we made you a farewell animation

Can you get the flag?

Beware headphone users! the music is loud.

*Solve* :
So, you get a swf file, transform it to fla <https://pdfrecover.herokuapp.com/swfdecompiler/>  
Doing a binwalk on it we see that there are more files in it, unzip it and look into the LIBRARY folder where you have Symbol3.xml, the flag is in it  
{{< highlight go >}}  brixelCTF{n0_m0r3_5upp0rt} {{< / highlight >}}  
### RIP FLASH, WE WILL MISS YOU

### The tape
I found this cassette tape from the '80s. I bet it has some cool games on it or something.

Better start looking for someone who grew up in that era... :)

*Solve*
Well after hours of pain I found out that the tape is an c64 -> decode the file from wav to c64 then play the file, and we got the flag :D

### Doc-deception
Need to hide something? why not a word document?

You need to dig deeper
*Solve* :
Well if you unzip the doc you get a flag.txt file, look into it and you get the file  

{{< highlight go >}}  brixelCTF{openxml} {{< / highlight >}}

### Limewire audio
I downloaded this sweet tune from limewire, but there's something weird going on  

can you find the hidden message?  

The flag is the name of the character in english, no spaces!  
*Solve* :
You get a .wav file, put it in sonic visualiser and add a spectrogram  

![test](lm.png)
I wonder who is that =)))))) 
The flag is up to you  to find it =)

### Conclusions 
I liked brixelCTF , it has some unique challs (NOTE : here aree not all challs , i wrote about  those who are very interesting)  
I want to thank  my team mates bec they helped me :D 





