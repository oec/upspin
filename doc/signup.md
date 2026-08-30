# Signing up a new user

> **The central key server is gone.**
> `key.upspin.io` was retired in 2025, so there is no public register to sign
> up to and no confirmation email to receive.
> What remains is generating a key pair, which is unchanged, and then making
> your public key known to the people you deal with.
> This document describes both: registering with a key server, if you or they
> run one, and the alternative, in which each side pins the keys it trusts.
> See [the config file](config.md) and `go doc upspin.io/key/trust`.

## Introduction

Before you sign up, you may want to read the
[Upspin overview](overview.md) document.
It introduces the concepts and terminology you'll need to understand to use the
system.

## Install the Upspin tools {#install}

To install the Upspin tools you must build them from source.

First [install Go](https://golang.org/doc/install) and then use `go get` to
fetch the Upspin tools and their dependencies and build them:

```
$ go install upspin.io/cmd/{upspin,cacheserver,upspin-audit,upspinfs}@latest
$ go install augie.upspin.io/cmd/upspin-ui@latest
```

This will install the Upspin commands to `$GOPATH/bin`, which you should add
to your system `PATH` if you haven't already.

They are:

- the `upspin` command-line tool (to create, access, share, and administer data
  stored in Upspin),
- the `upspin-ui` graphical user interface (a visual helper for signing up,
  deploying Upspin servers, and working with Upspin data),
- the `cacheserver` daemon (a cache for remote Upspin data),
- the `upspin-audit` command-line tool (for auditing storage consumption),
- and, on macOS and Linux systems, the `upspinfs` program
  (a [FUSE](https://github.com/libfuse/libfuse) filesystem, to mount the Upspin
  file system in your local file tree).

## Create an Upspin user {#signup}

You will need to choose an Upspin user name, which is just an email address you
own.
Your user name is how the Upspin system and its users will identify you and your
files.
If you register with a key server, your chosen user name becomes a matter of
public record in that server's log.

Any valid email address is almost certainly a valid Upspin user name
(see [the faq](faq.md#email-restrictions) for the exceptions to this).

> You may use your regular email address or an Upspin-specific one; either way
> is fine.
> The address appears in any Upspin path name you share, and in a key server's
> log if you use one, so be sure your email account has whatever spam,
> anonymity, or other protection you feel is necessary.
>
> No email will be sent to the address after this signup step. All future
> Upspin operations, even updating later to a new key pair, will be validated
> exclusively with the key pair generated during signup.
> Someone with future access to your email can’t masquerade as you in Upspin.
> Conversely, if you lose your keys your email account is not useful for
> recovery.

If you are planning to join an existing Upspin directory and store server,
before starting the next step with `upspin-ui`,
make sure to ask the administrator to add your user name to the server's
`Writers` group. (They'll know what to do.)
This will grant you permission to create your user root in that directory
server and store data in that store server.

**Generate your key pair.**

	upspin keygen -secretseed "" $HOME/.ssh/you@example.com

This writes `public.upspinkey` and `secret.upspinkey` to that directory. The
secret key never leaves your computer.

`keygen` prints a "secret seed" that
serves as a human-readable version of the key.
(The computer-readable version is just a very long number.)
**Write down this secret seed, keep it somewhere safe and do not lose it. It is
literally your key to Upspin.**

> Upspin's security model is based on public key encryption, in which each
> Upspin user has a pair of keys called the public and private keys.
> The public key is meant to be known to everyone, while the private key is
> kept in secret by the user, such as on a local workstation or other private
> device.
>
> It is vital that you do not lose or share your secret key or its "secret
> seed" (which is equivalent to the key itself).
> **If you lose your key and its secret seed
> you will lose access to this Upspin identity,
> including all the data you have stored and even the ability
> to use your registered user name.**
> There is no way to recover a lost key.
> The high security that Upspin offers would be compromised if
> there were an account recovery mechanism.

**Then make your public key known.** There are two ways, and which one applies
depends on whether anyone you deal with runs a key server.

*With a key server.* Run `upspin signup -key=<address> -dir=<address>
-store=<address> you@example.com`. The `-key` flag is required; there is no
default. That server sends a confirmation email, and visiting the link in it
proves you control the address and completes the registration.

> From here on, the email address serves as your Upspin user name.
> However, after this account verification step Upspin will never use it as an
> actual email address again.
> At this point you could even cancel the email account, if you chose to do so,
> without affecting your Upspin user name.
> In fact, even if the email account is later hijacked, the
> attacker will not be able to get access to your Upspin account.

*Without one.* There is nothing to register with, so instead you hand your
record to the people who are to trust it. Write it out with

	upspin user > you.yaml

and send them the file by any means; they pin it with

	upspin keytrust -add -fingerprint=<fingerprint> -in=you.yaml

after checking the fingerprint, which `upspin user` also prints, against a copy
you give them by some route an attacker does not control. If your domain has a
trust anchor, signing the record with `upspin keysign` saves each of them that
check. See `go doc upspin.io/key/trust`.

## Nominate (and maybe deploy) your Upspin servers {#deploy}

> The `upspin-ui` program referred to below lives in a separate repository, and
> its option to deploy to the Google Cloud Platform depends on storage backends
> that have moved out of this one; only the local disk backend remains here.
> To set up a server by hand, and with local storage, follow
> [Setting up `upspinserver`](server_setup.md) instead.
> The `dirserver:` and `storeserver:` lines it describes are the same either
> way; see [the config file](config.md).

Next you need to decide whether you are going to deploy your own Upspin
directory and store servers, use those maintained by someone else, or
skip specifying Upspin servers entirely.

After you have registered your account, `upspin-ui` prompts you to select one
of three options:

- I will use existing Upspin servers.
- I will deploy new Upspin servers to the Google Cloud Platform.
- Skip configuring my servers; I'll use Upspin in read-only mode for now.

Choose the first option if you want to use Upspin servers provided by somebody
else, or if you want to deploy your own servers manually (see the [Setting up
`upspinserver`](server_setup.md) document for how to do this).

Choose the second option to deploy your servers to the Google Cloud Platform
using the `upspin-ui` program, and follow the on-screen instructions to
complete the deployment.

Choose the third option if you wish to use Upspin as a read-only user.

> If you're unsure, choose the third option, as you can always go back to this
> step later.
>
> To go back, edit your `$HOME/upspin/config` file and remove its `dirserver:`
> and `storeserver:` lines and restart `upspin-ui`.

## Creating your Upspin directory {#mkdir}

Whether you chose to use existing servers or to deploy your own, the `upspin-ui`
program will attempt to create a directory in the nominated directory server
that will host your Upspin tree (your "user root").

With the servers running and granting you access permission, and with your
correct information registered in the key server, `upspin-ui` will create
your user root and display its contents.

## Hello, world {#hello}

To prove that your user root was created successfully, try copying a file to
the system.

Do this by dragging a file into the `upspin-ui` directory pane.
If the directory pane refreshes and your file is there, then you are ready to
use Upspin.
If something is wrong then you will see an error message.

Another way is to use the `upspin cp` command:

```
$ upspin cp ./hello.jpg you@gmail.com/
```

To check that everything worked, copy it back and verify its contents:

```
$ upspin cp you@gmail.com/hello.jpg ./ciao.jpg
$ sum hello.jpg ciao.jpg
1600 21 hello.jpg
1600 21 ciao.jpg
```

Although the `upspin-ui` and `upspin` tools support all the functionality of
the system, for smoother operation you may want to install the FUSE daemon,
`upspinfs`, and a cache server that improves performance.
The cache server is particularly important, and the setup instructions are in
the [Upspin configuration](config.md) document.

## Browsing Upspin Files on Linux and macOS {#upspinfs}

Upspin includes a tool called `upspinfs` that creates a virtual filesystem
where you can access the Upspin name space as a regular mounted file system.

Here is an example of its use.

Make a directory in which to mount the Upspin name space:

```
$ mkdir $HOME/up
```

Then run the `upspinfs` command giving that directory as its sole argument:

```
$ upspinfs $HOME/up
```

Now you have access to the full Upspin name space:

```
$ ls $HOME/up/you@gmail.com
```

The `upspinfs` command will exit when the file system is unmounted.

If you encounter an error when you run `upspinfs` the second time, such as:

```
mount helper error: fusermount: failed to open mountpoint for reading: Transport endpoint is not connected
fuse.Mount failed: fusermount: exit status 1
```

just unmount the directory and try again.

To learn more about `upspinfs`, see [its documentation](https://godoc.org/upspin.io/cmd/upspinfs).
