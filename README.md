# Websteps illustrated

This repository contains code that helps understanding the
new OONI experiment called websteps.

## Nginx setup

```
  # [sbs] hack to test the websteps wss based TH
  location /websteps/v1/th {
      proxy_read_timeout 900;
      proxy_pass http://127.0.0.1:9876;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "Upgrade";
      proxy_set_header Host $host;
  }
```
