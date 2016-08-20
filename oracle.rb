require 'openssl'

block_size = 8 # DES has a block size of 64 bits = 8 bytes

# Construct an oracle which returns false if there is a padding
# error
def oracle(ciphertext)
  decipher = OpenSSL::Cipher::DES.new(:CBC)
  decipher.decrypt
  decipher.key = 'opensesame'
  decipher.iv = "\x01\x02\x03\x04\x05\x06\x07\x08"
  decipher.update(ciphertext)
  decipher.final

  true
rescue OpenSSL::Cipher::CipherError
  false
end

# Generate the ciphertext
cipher = OpenSSL::Cipher::DES.new(:CBC)
cipher.encrypt
cipher.key = 'opensesame'
cipher.iv = "\x01\x02\x03\x04\x05\x06\x07\x08"

m = 'Computation Club is rather good'
m0, m1, m2, m3 = m.unpack('C*').each_slice(block_size).entries
puts "m0: #{m0.inspect}"
puts "m1: #{m1.inspect}"
puts "m2: #{m2.inspect}"
puts "m3: #{m3.inspect}"

ciphertext = cipher.update(m) + cipher.final

# Split the ciphertext into blocks
c0, c1, c2, c3 = c = ciphertext.unpack('C*').each_slice(block_size).entries
puts "c0: #{c0.inspect}"
puts "c1: #{c1.inspect}"
puts "c2: #{c2.inspect}"
puts "c3: #{c3.inspect}"

puts (2..c.size).flat_map { |slice|
  m = Array.new(block_size)
  *_, previous_block, target_block = c[0, slice]

  7.downto(0).each do |i|
    pad = block_size - i
    padding_size = block_size - i - 1

    m[i] = (0..255).find { |g|
      oracle(
        (
          previous_block[0, i] +
          [previous_block[i] ^ g ^ pad] +
          padding_size.downto(1).map { |j| previous_block[block_size - j] ^ m[block_size - j] ^ pad } +
          target_block
        ).pack('C*')
      ) && pad != g
    } || pad
  end

  m
}.tap { |x| puts x.inspect }.pack('C*')
