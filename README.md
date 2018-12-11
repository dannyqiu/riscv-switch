Tiny RISC-V emulation distributed across a network of P4-programmable switches

# Build and run code

Run `make` to build and run the P4 switch in a mininet environment. The controller in
`controller.py` will run automatically and configure the switches in the network topology (defined
in `topology.json`) to perform the RISC-V emulation. Host `h99` in the network topology,
representing the external datastore, will automatically run in the background the datastore server
defined in `datastore.py`. In the case that it does not start automatically, start the datastore by
executing the Python script on host `h99`.

# Execute Tiny RISC-V programs

The network topology is configured with 3 hosts that can send Tiny RISC-V assembly programs to the
load balancer for execution within the network. These hosts are `h1`, `h2`, and `h3`. To open up a
command line on a host, run `xterm <host1> [<host2> <host3> ...]` in the mininet REPL.

Run the receiver on the host from which you will be sending the programs: `./receive.py`

To send a test program that executes each of the available Tiny RISC-V assembly instructions: `./send.py`

To send a test program that computes the 8th Fibonacci number: `./fibonacci.py`

Users can execute arbitrary Tiny RISC-V assembly programs by using the instruction types defined in
`headers.py` and sending the programs to the load balancer using a script similar to `fibonacci.py`.
