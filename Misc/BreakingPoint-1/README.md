# Breaking Point 1
- **author:** 
- **category:** Misc
- **difficulty:** {Easy, Medium, Hard, Expert}

## Description:
Python sanbox challenge.

### Explaination
Because `blacklist` is defined as a global variable within the `main()` function, we are able to clear it's contents so that there is no longer a blacklist limiting our moves. 
```python
blacklist.clear()
print(open("flag.txt").read())
```


## Flag format:

`GrizzCTF{}`

## Build instructions (if any):

```bash
cd build/
docker build -t breaking-point .
```

## Running the challenge container:

```bash
docker run -p 8888:8888 -d -it breaking-point
```

### Solution

```python
blacklist.clear()
print(open('flag.txt').read())
```

---
