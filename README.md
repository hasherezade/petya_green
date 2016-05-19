# petya_green
Application for random attack on Green Petya's key
-
<b>WARNING!</b> This is just an experiment! 
Efficiency of this application is much, much lower than the previous solution (for Red Petya).
I am making it available for the people who want to participate in the experiment of unlocking Green Petya - due to the fact that the previous solution does not work at all.

<b>USAGE</b><br/>
1) If you have a key and you want to test it:<br/>
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green disk_fragment.bin nGuJGbmDuVN9XmLa
[+] Petya bootloader detected!
[+] Petya http address detected!
[+] Petya FOUND on the disk!
---
verification data:
34 80 15 1a d1 76 5c 7b 60 2b e3 d0 d0 ae f8 c2 

nonce:
07 0c 12 f6 79 28 73 cb 
---

decoded data:
07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 

[+] nGuJGbmDuVN9XmLa is a valid key
</pre>
2) If you don't have a key and you want to search it:
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green disk_fragment.bin
[+] Petya bootloader detected!
[+] Petya http address detected!
[+] Petya FOUND on the disk!
---
verification data:
34 80 15 1a d1 76 5c 7b 60 2b e3 d0 d0 ae f8 c2 

nonce:
07 0c 12 f6 79 28 73 cb 
---
The key will be random!
Please wait, searching key is in progress...
</pre>
