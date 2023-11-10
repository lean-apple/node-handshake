# P2P Handshake with Bitcoin Protocol

Test Bitcoin Protcol handshake, an important step to establish communication between two nodes on the Bitcoin network.

It contains 2 major steps after initializing the communication between  two nodes : 
- Sending a `version` message to the node
- Receiving a `vertrack` response 
 
 Complete documentation on the global Bitcoin message, `version` and `vertrack` messages can be found here : [Official Bitcoin Wiki](https://en.bitcoin.it/wiki/Protocol_documentation).

## Run

### Set-up for local run 

The work lies on running in parallel a Bitcoin node for the regtest Network. 

You need to download up a bitcoin node implementation depending on your OS. 

Once it is done, Bitcoin node can be launched : 

```sh
bitcoind -regtest
```
It will listen by default on `18444` port.

and then you can launch the run :

```sh
cargo run
```

### GHA run

All the steps mentionned to set up a Bitcoin node and run the handshake code on Linux env are launched through the GHA's ci.
It can help also to see how to set up the `Bitcoin.conf` configuration file. 

## Test

A couple of tests are available either as unit tests for modules or either for the ones related to handshake at the following path : `/test/test.rs`. 

You can launch them by this way : 

```sh
cargo test
```

## Code architecture considerations

As explained in next steps, the code is run only at the moment for `regtest` Network and has been simplified for the purpose.

Some ideas to improve it, would be to : 
- Add `cargo` command arguments to launch it dependeding on the network and also ideally pick a specific IP
- Optimize link between different kinds of message to move more easily from `BitcoinMessage` to `verack`
- Make error handling more consistent
- Test it through multiple nodes scheme