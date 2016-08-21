require 'cipher'
require 'oracle'

# A helper class to encrypt plain text and to decrypt and validate the padding of ciphertext
cipher = Cipher.new('DES-CBC')

# Our plain text message, given on STDIN
plaintext = ARGF.read

# Split our message into blocks appropriate for our cipher choice and print them
cipher.split(plaintext).each_with_index do |block, i|
  puts "m[#{i}] = #{block.inspect}"
end

# Encrypt our message
ciphertext = cipher.encrypt(plaintext)

# Split the ciphertext into appropriate blocks
ciphertext_blocks = cipher.split(ciphertext)
ciphertext_blocks.each_with_index do |block, i|
  puts "c[#{i}] = #{block.inspect}"
end

decrypted_plaintext = Oracle.new(cipher).attack(ciphertext)

puts "m = #{decrypted_plaintext}"
