---
title: "Playit CTF 2026 qual"
description: "okay CTF"
date: 2025-06-24
summary: "Team: @PETIR | Pyjail misc chalenge."
tags: ["Misc"]
categories: ["Writeups"]
showTableOfContents: true
draft: false
---
Team : @PETIR

### Title : Translator Magang
```
Seorang mahasiswa sedang magang di kedutaan besar Zalgo untuk indonesia sebagai translator, tapi dia kadang masih salah paham dengan pekerjaannya.

Author: eeswepe
```

![a](/images/zalgo1.png)

Starting off the challenge, the server was asking the input to talk in zalgo language after a google search I found a zalgo encoder

https://lingojam.com/ZalgoText

So everything that I input must first be encoded in zalgo for the server to decode then take

![a](/images/zalgo2.png)

After a bit of testing I finally found something

based on the test in my imagination the server problably does

```python
userInput = input()
eval(decodeZalgo(userInput))
```

And also after a bit of testing I found out that there are blacklists used and a user input limit used that limits our input to \<25 chars

So the server logic is problably similar to

```python
userInput = input()
if userInput >= 25:
    exit()
else:
    eval(decodeZalgo(userInput))
```

![Description of image](/images/zalgo3.png)

I have confirmed that the `__` syntax works so lets continue

Usually in a pyjail situation we should target the `open` method to get file read the problem is in this challenge the system limits us to only 24 characters this makes our payload space fairly small

But the funny thing was while i was testing i found out that `eval()` and `input()` was not banned

![Description of image](/images/zalgo4.png)

I saw that the second input was not filtered because the length check was on a different part of the code
Then I thought what if we recalled `eval()` and then pass our newly created `input()` to the `eval()`?

![Description of image](/images/zalgo5.png)

As you can see our long equation runs this bypasses the character limit and makes everything much easier

The only thing that we need to bypass is the hidden blacklist

Starting from a random python function

![Description of image](/images/zalgo6.png)

So the main targets in ssti are dict and dir and i successfully called the dictionary and actually found `open` in the methods

So we could possibly get the flag via

```python
len.__self__.__dict__.['open']('/etc/passwd').read()
```

But sadly the word `open` and `read` was banned

But the good this is because this is python we can forge the word `open` by doing `'o' + 'pen'` this bypasses the check if it checks the input only when it was taken

And for the `.read()` we actually not really need that because we can just change the value of our `open` method into a list

![Description of image](/images/zalgo7.png)

Funny enough the word `flag` was also banned so we could also forge the filename

![Description of image](/images/zalgo8.png)

Pretty easy challenge :D

{{< alert icon="check-circle" cardColor="#10b981" >}}
**Flag :** `PLAYIT{w1_w0k_d3_T0K_N0t_Onle_ToK_d3_T0k}`
{{< /alert >}}