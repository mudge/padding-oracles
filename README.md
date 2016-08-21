# Padding Oracle Attack

For the [23rd August 2016 meeting of London Computation Club](http://lanyrd.com/2016/london-computation-club-cryptography/), this is a proof of concept implementation of a [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack) in Ruby. It can decrypt both DES and AES encrypted ciphertexts using [cipher block chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29).


## Usage

```shell
$ printf 'This is an extremely sensitive matter: for your eyes only!' | ruby -Ilib encrypt.rb | ruby -Ilib oracle_attack.rb
an extremely sensitive matter: for your eyes only!
```

## License

Copyright © 2016 Paul Mucur.

Distributed under the MIT License.
