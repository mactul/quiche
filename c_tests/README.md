This folder provide a simple example of an HTTP client (almost the same as quiche/examples/client.rs) in C using the quiche ffi.  
It can be used with the server in apps/src/bin/quiche-server.rs

To run the server, go at the root of the repository and run:
```sh
RUST_LOG=trace cargo run --bin quiche-server -- --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --root .
```

To compile the client, you have to install the latest version of powermake
```sh
pip3 install -U powermake
```

Then you can simply run:
```sh
python c_tests/makefile.py -bt https://127.0.0.1:4433/README.md 
```

or in debug if you prefer:
```sh
python c_tests/makefile.py -bdt https://127.0.0.1:4433/README.md 
```

If you really want to use a Makefile instead of PowerMake, PowerMake can generate one with:
```sh
python c_tests/makefile.py -m
```

or in debug:
```sh
python c_tests/makefile.py -md
```