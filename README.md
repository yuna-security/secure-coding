# Secure Coding

## Tiny Secondhand Shopping Platform

You should add some functions and complete the security requirements.

## Requirements

If you do not have Miniconda (or Anaconda), install it from:
https://docs.anaconda.com/free/miniconda/index.html

```bash
git clone https://github.com/yuna-security/secure-coding.git
cd secure-coding
conda env create -f enviroments.yaml
```

## Usage

Run the server process:

```bash
python app.py
```

For temporary external testing, ngrok can forward port 5000:

```bash
# optional
sudo snap install ngrok
ngrok http 5000
```

> This README currently reflects the mentor starter baseline. It will be
> expanded with the final secure setup, configuration, migration, test, and
> execution instructions as implementation progresses.
