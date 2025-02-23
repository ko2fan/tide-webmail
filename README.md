# TIDE

TIDE is a REST API that a website can use to retrieve folders and emails using IMAP4.

This is a WIP project that is still very much in development. I would not advise using in production.

# Contents

- [Why?](#why)
- [What the API provides](#what-the-api-provides)
- [Dependencies](#dependencies)
- [Usage](#usage)
- [Author](#author)

### Why?

---
I wanted a flexible, yet fast way of providing web access to multiple IMAP servers.

### What the API provides

---
- /login - Let's a user specify a username, password and IMAP server host:port
- /folders - Retrieves a list of folders from the IMAP mailbox
- /emails - Retrieves the email envelopes for emails in a folder
- /email - Retrieves the email body in plain and HTML formats

### Dependencies

---
This uses:

- [`go-imap`](github.com/emersion/go-imap)
- [`uuid`](github.com/google/uuid)

### Usage

---

```bash
$ go build main.go
$ go run main.go
```


### Author
---

I am David Athay and I am currently building one of the largest mail platforms in Europe,
