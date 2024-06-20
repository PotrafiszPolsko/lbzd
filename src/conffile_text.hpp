#ifndef CONFFILE_TEXT_HPP
#define CONFFILE_TEXT_HPP

#include <string>

const std::string conffile_text =
R"(# Add a node to connect. Format: <ip>:<port>
# addnode = 192.168.1.4:22083

# Bind to given address and always listen on it
# bindport = 22083

# Bind to given address and always listen on it
# bindaddress = 0.0.0.0

# Hidden service port
# onionport = 22086

# Enable connection to seed node
# enable-seed-node-connection = true

# Specify data directory
# datadir = ./ivoting

# Number of threads
# par = 0

# RPC address for TCP socket
# rpc-tcp-address = 127.0.0.1

# RPC Port for TCP socket (default: 22084)
# rpc-tcp-port = 22084

# rpcuser
# rpcpassword)";

#endif // CONFFILE_TEXT_HPP
