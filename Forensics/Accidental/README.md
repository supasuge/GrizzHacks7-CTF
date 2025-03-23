# Accidental
- Author: [supasuge](https://github.com/supasuge)
- Category: Forensics
- Difficulty: Easy

## Description

A disgruntled employee appears to have made quite the exit and deleted some important file's from the backup USB the team project is kept on. Are you able to recover this file somehow and retrieve the deleted contents? It would be a lifesaver, good luck!

## Distributable files

`usb_fs.zip` - Contains `usb_image.dd`, a FAT filesystem drive in which I simply created the flag on it, then deleted it and filled the rest of the drive with zeros. Im classy like that...

## Flag Format

`GrizzCTF{...}`

### Solution

To solve this challenge, you can either use one of the tools from `SleuthKit`, `Autopsy`, or a classic such as `testdisk`. Simply open the .dd file using your tool of choice, then extract the deleted file back onto your system (`flag.txt`).
