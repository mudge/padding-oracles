require 'cipher'
require 'oracle'

ARGF.binmode

cipher = Cipher.new('DES-CBC')
cipher.key = 'opensesame'
cipher.iv = "\x0\x1\x2\x3\x4\x5\x6\x7"
ciphertext = ARGF.read

# Attack the ciphertext and print the decrypted plaintext
decrypted_plaintext = Oracle.new(cipher).attack(ciphertext)

$stdout << decrypted_plaintext
