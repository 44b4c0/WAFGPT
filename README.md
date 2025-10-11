# WAFGPT

### Introduction

**WAFGPT** is an AI which analyzes HTTP traffic in order to find malicious contents. The project has its own data parsing and AI training capabilities but it's also possible to create a RAG system with LLamaCPP in order to load custom AI models to analyze HTTP traffic.

### How to setup

In order to setup **WAFGPT** you need to create a virtual environment and install dependencies with `pip install -r requirements.txt` command. After that you can run `main.py` and necessary choose options.

### Project structure

Project has several folders that are required for AI training and data parsing.

`main.py` - is a file which is the main script and entry point of the program. use `python -B main.py` to start the program.
`config.py` - is a file that contains various constants and paths that are required for the code to run correctly.
`modules/` - is a folder/directory that contains modules for `main.py`. Currently, there are 4 modules.
`modules/aitrainer.py` - is a file that contains classes and functions for custom AI training.
`modules/api.py` - is a file that contains functions for Flask HTTP API.
`modules/dataparser.py` - is a file that contains functions for Data parsing and output management.
`modules/llamacpp.py` - is a file that contains a RAG system for LLamaCPP integration.
`datain/` - is a folder/directory that contains files for data input when training a custom AI or giving the AI data to analyze.
`dataout/` - is a folder/directory that contains files that was processed during parsing or conversion.
`ai/` - is a folder/directory that contains the custom trained model(PKL & PTH files) and/or other AI model(GGUF file)
