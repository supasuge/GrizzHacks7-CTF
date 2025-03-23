# Spectacular
- **Author:** [supasuge](https://github.com/supasuge) | Evan Pardon
- **category:** Forensics/RFz
- **difficulty:** Easy
- **Points**: 100

## Description:

We've intercepted a mysterious audio transmission, but something seems off. When played it just sounds like static, and reducing noise does nothing; perhaps there's more than meets the eye. Can you uncover the hidden message?

Note: Makes sure your flag submission if wrapped in `GrizzCTF{}`

## Flag format

`GrizzCTF{...}`

## Distributable files
- `challenge.wav`: Contains the audio transmission with the spectogram revealing the flag.



#### Solution

You can either open the file using `audacity` and see the flag in the spectrogram view or you can use the `sox` tool to convert the `.wav` file to a spectrogram image.
