require 'cipher'

ARGF.binmode

cipher = Cipher.new('DES-CBC')
cipher.key = 'opensesame'
cipher.iv = "\x0\x1\x2\x3\x4\x5\x6\x7"
ciphertext = ARGF.read

$stdout << cipher.decrypt(ciphertext)
