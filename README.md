# rustsecp
Security Plugins in Rust

This is a basic example of a C-compatable Db2 Security plugin created in Rust.  It is meant to demonstrate that FFI-style Rust code can be called from Db2.

The security plugin is very simple and meant to demonstrate interoperability.  It is not considered a secure implementation and should not be used in production.

## Compile Rust Code

Compile the shared library as any other Rust project:

```sh
cargo build --release
```

## Copy the library to the Db2 server

Copy the file `target/release/libdb2rustsecp.so` to the `~/sqllib/security64/plugin/server` directory on the Db2 server.

## Configure Db2 to use the plugin

Update the DBM CFG with the value of the plugin.  As this is not a dynamic parameter, a db2stop/db2start is required.

```
db2stop
db2 update dbm cfg using srvcon_pw_plugin libdb2rustsecp
db2start
```

## Test CONNECT

The users and passwords are defined in the plugin as this is just a demo.  Try connecting:

```
$ db2 connect to testdb user newton using newtonpw

   Database Connection Information

 Database server        = DB2/LINUXX8664 11.5.8.0
 SQL authorization ID   = NEWTON
 Local database alias   = TESTDB
```