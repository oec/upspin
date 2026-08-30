# Upspin architecture

Each user of the system is represented by an Upspin user name, which looks like
an email address; a public/private key pair; and the network address of a
directory server:

![User diagram](images/arch/user.png)

That directory server holds a hierarchical tree of names pointing to the user's
data, which is held in a store server, possibly encrypted.
Each item in the tree is represented by a directory entry containing a list of
references that point to data in the store server:

![Directory and Store server diagram](images/arch/dirstore.png)

All the users are connected through a key server, which holds the public key and
directory server address for each user. The project ran a central one at
`key.upspin.io` until 2025; a configuration now names its own, or pins the
records it trusts locally instead. See [the config file](config.md).

![Key server diagram](images/arch/key.png)

This is how the pieces fit together:

![Overall system diagram](images/arch/overall.png)

From top to bottom, these represent:

- Shared directory and store servers used by multiple users.
- A single-user system with a combined directory and store server.
- A camera served by a special-purpose combined directory and store server.

To illustrate the relationship between these components, here is the sequence
of requests a client exchanges with the servers to read the file
`augie@upspin.io/Images/Augie/large.jpg`:

![Reading a file diagram](images/arch/readfile.png)

1. The client asks the key server for the record describing the owner of the
   file, which is the user name at the beginning of the file name (`augie@upspin.io`).
   The response contains the name of the directory server holding that user's
   tree and Augie's public key. (The diagrams name `dir.upspin.io` and
   `store.upspin.io`, the servers the project ran; read them as stand-ins for
   whichever servers a deployment uses.)
2. The client asks the directory server for the directory entry describing the
   file. The response contains a list of block references, which include the
   name of the store server.
3. The client can then ask the store server for each of the blocks, pipelining
   the requests for efficiency.
4. The client decrypts the blocks (using Augie's public key) and concatenates
   them to assemble the file.
