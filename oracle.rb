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

m0 = Array.new(8)

7.downto(0).each do |i|
  m0[i] = (0..255).find { |g|
    pad = block_size - i
    padding_size = block_size - i - 1

    oracle(
      (
        c0[0, i] +
        [c0[i] ^ g ^ pad] +
        padding_size.downto(1).map { |j| c0[block_size - j] ^ m0[block_size - j] ^ pad } +
        c1
      ).pack('C*')
    )
  }
end

m1 = Array.new(8)

7.downto(0).each do |i|
  m1[i] = (0..255).find { |g|
    pad = block_size - i
    padding_size = block_size - i - 1

    oracle(
      (
        c0 +
        c1[0, i] +
        [c1[i] ^ g ^ pad] +
        padding_size.downto(1).map { |j| c1[block_size - j] ^ m1[block_size - j] ^ pad } +
        c2
      ).pack('C*')
    )
  }
end

m2 = Array.new(8)

7.downto(0).each do |i|
  m2[i] = (0..255).find { |g|
    pad = block_size - i
    padding_size = block_size - i - 1

    oracle(
      (
        c0 +
        c1 +
        c2[0, i] +
        [c2[i] ^ g ^ pad] +
        padding_size.downto(1).map { |j| c2[block_size - j] ^ m2[block_size - j] ^ pad } +
        c3
      ).pack('C*')
    )
  }
end

puts (m0 + m1 + m2).pack('C*')
