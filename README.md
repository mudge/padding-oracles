# Padding Oracle Attack

For the [23rd August 2016 meeting of London Computation Club](http://lanyrd.com/2016/london-computation-club-cryptography/), this is a proof of concept implementation of a [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack) in Ruby. It can decrypt both DES and AES encrypted ciphertexts using [cipher block chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29).


## Usage

```shell
$ echo 'This is an extremely sensitive matter: for your eyes only!' | ruby -Ilib oracle_attack.rb
m[0] = [84, 104, 105, 115, 32, 105, 115, 32]
m[1] = [97, 110, 32, 101, 120, 116, 114, 101]
m[2] = [109, 101, 108, 121, 32, 115, 101, 110]
m[3] = [115, 105, 116, 105, 118, 101, 32, 109]
m[4] = [97, 116, 116, 101, 114, 58, 32, 102]
m[5] = [111, 114, 32, 121, 111, 117, 114, 32]
m[6] = [101, 121, 101, 115, 32, 111, 110, 108]
m[7] = [121, 33, 10]
c[0] = [183, 122, 117, 31, 33, 38, 84, 79]
c[1] = [9, 248, 61, 135, 34, 3, 30, 191]
c[2] = [220, 248, 10, 226, 141, 79, 109, 21]
c[3] = [124, 211, 87, 139, 199, 113, 66, 211]
c[4] = [198, 171, 15, 95, 153, 168, 183, 118]
c[5] = [90, 62, 185, 156, 123, 1, 106, 171]
c[6] = [142, 126, 10, 250, 179, 0, 70, 161]
c[7] = [129, 175, 135, 235, 116, 2, 193, 96]
m = [97, 110, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 115, 101, 110, 115, 105, 116, 105, 118, 101, 32, 109, 97, 116, 116, 101, 114, 58, 32, 102, 111, 114, 32, 121, 111, 117, 114, 32, 101, 121, 101, 115, 32, 111, 110, 108, 121, 33, 10, 5, 5, 5, 5, 5]
m = an extremely sensitive matter: for your eyes only!
```

## License

Copyright © 2016 Paul Mucur.

Distributed under the MIT License.
