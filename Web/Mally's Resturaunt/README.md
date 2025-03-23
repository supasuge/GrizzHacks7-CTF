# Mally's Resturaunt 🍖

- **Author:** Max Glisky - ([mng48301](https://github.com/mng48301))
- **Category:** Web
- **Difficulty:** Easy

**Port Needed:** $80$

## Description

Welcome to Mally's Restaurant, where we serve the finest dishes crafted with love and the freshest ingredients. Our menu features a variety of culinary delights that cater to all taste buds. Whether you're in the mood for a hearty meal or a light snack, Mally's has something for everyone.

For those with a keen eye and a curious mind, there's always more to discover at Mally's. Sometimes, the best secrets are hidden in plain sight.

Happy dining and happy hunting!

## Flag Format
```txt
GrizzCTF{<secret_message>}
```

## Build instructions

```bash
~/ [$] cd web_challenge1/build
~/web_challenge1/build [$] docker build -t my-nginx-website .
```


## Running the challenge container:

```bash
~/web_challenge1/build [$] docker run -d -p 80:80 my-nginx-website

open http://localhost:80
```

#### Hint

```
Inspect the food closely; you might find what you are looking for. 
```

