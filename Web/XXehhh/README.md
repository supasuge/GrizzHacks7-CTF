# XXehhh
- Author: [supasuge](https://github.com/supasuge) | Evan Pardon
- Category: Web
- Difficulty: Easy/Medium


## Build

```bash
cd build
docker build -t xxehhh .
```

## Deploy the container
- Port needed: 80

```bash
docker run -d -it -p 80:8000 xxehhh
```

### Solution

XXE PHP path injection via `php://filter`.
