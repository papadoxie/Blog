<< [Back to Home](https://papadoxie.github.io)

# Cache Me Outside
## Write-up of the PicoCTF Binary Exploitation Challenge

<img	src="./ChallengeDescription.png"
		alt="Challenge Description"
/>

## Setup

3 files are provided to us for the challenge and the address
to the server is also provided.

Lets download the files and try to run the binary

<img	src="./Setup0.png"
		alt="Challenge Description"
/>

We get a crash
This occurs because our linker is a newer version than the libc provided

<img	src="./Setup1.png"
		alt="Challenge Description"
/>

We can fix this using pwninit which will automatically take care of this

<img	src="./Setup2.png"
		alt="Challenge Description"
/>

Lets try running it now

<img	src="./Setup3.png"
		alt="Challenge Description"
/>

Hmm, it still crashes  
Lets open the binary in Ghidra and take a look at whats going on

## Analysis

## Exploitation