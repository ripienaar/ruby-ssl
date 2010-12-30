What is it?
===========

A class that assists in encrypting and decrypting data using a
combination of RSA and AES

Data will be AES encrypted for speed, the Key and IV used in
the AES stage will be encrypted using RSA

   ssl = SSL.new(public_key, private_key, passphrase)

   data = File.read("largefile.dat")

   crypted_data = ssl.encrypt_with_private(data)

   pp crypted_data

This will result in a hash of data like:

   crypted = {:key  => "crd4NHvG....=",
              :iv   => "Ny2BPOPj....=",
              :data => "XWXlqN+i...=="}

The key, iv and data will all be base 64 encoded already

You can pass the data hash into ssl.decrypt_with_public which
should return your original data

There are matching methods for using a public key to encrypt
data to be decrypted using a private key

Licence?
========

Apache 2.0

Contact?
========

R.I.Pienaar / rip@devco.net / www.devco.net / @ripienaar
