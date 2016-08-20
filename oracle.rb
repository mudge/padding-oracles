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
c0, c1, c2, c3 = ciphertext.unpack('C*').each_slice(block_size).entries
puts "c0: #{c0.inspect}"
puts "c1: #{c1.inspect}"
puts "c2: #{c2.inspect}"
puts "c3: #{c3.inspect}"

# We're trying to recover this whole block of plain text
m1 = Array.new(8)

# Let's try to decrypt c1 starting from the last character
# g is our guess
m1[7] = (0..255).find { |g|

  # Let's just take c0 + c1 and forget c2 and c3
  # Let's guess the last byte of c1 by XORing it with our guess and \x01
  # If it returns true then we've discovered the last byte of c1!
  oracle(
    (
      c0 +
      c1[0, 7] +
      [c1[7] ^ g ^ 1] +
      c2
    ).pack('C*')
  )
}

m1[6] = (0..255).find { |g|

  # Let's do the next one by making the padding 2 2
  oracle(
    (
      c0 +
      c1[0, 6] +
      [
        c1[6] ^ g ^ 2,
        c1[7] ^ m1[7] ^ 2
      ] +
      c2
    ).pack('C*')
  )
}

m1[5] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      c1[0, 5] +
      [
        c1[5] ^ g ^ 3,
        c1[6] ^ m1[6] ^ 3,
        c1[7] ^ m1[7] ^ 3
      ] +
      c2
    ).pack('C*')
  )
}

m1[4] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      c1[0, 4] +
      [
        c1[4] ^ g ^ 4,
        c1[5] ^ m1[5] ^ 4,
        c1[6] ^ m1[6] ^ 4,
        c1[7] ^ m1[7] ^ 4
      ] +
      c2
    ).pack('C*')
  )
}

m1[3] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      c1[0, 3] +
      [
        c1[3] ^ g ^ 5,
        c1[4] ^ m1[4] ^ 5,
        c1[5] ^ m1[5] ^ 5,
        c1[6] ^ m1[6] ^ 5,
        c1[7] ^ m1[7] ^ 5
      ] +
      c2
    ).pack('C*')
  )
}

m1[2] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      c1[0, 2] +
      [
        c1[2] ^ g ^ 6,
        c1[3] ^ m1[3] ^ 6,
        c1[4] ^ m1[4] ^ 6,
        c1[5] ^ m1[5] ^ 6,
        c1[6] ^ m1[6] ^ 6,
        c1[7] ^ m1[7] ^ 6
      ] +
      c2
    ).pack('C*')
  )
}

m1[1] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      c1[0, 1] +
      [
        c1[1] ^ g ^ 7,
        c1[2] ^ m1[2] ^ 7,
        c1[3] ^ m1[3] ^ 7,
        c1[4] ^ m1[4] ^ 7,
        c1[5] ^ m1[5] ^ 7,
        c1[6] ^ m1[6] ^ 7,
        c1[7] ^ m1[7] ^ 7
      ] +
      c2
    ).pack('C*')
  )
}

m1[0] = (0..255).find { |g|

  # And so on...
  oracle(
    (
      c0 +
      [
        c1[0] ^ g ^ 8,
        c1[1] ^ m1[1] ^ 8,
        c1[2] ^ m1[2] ^ 8,
        c1[3] ^ m1[3] ^ 8,
        c1[4] ^ m1[4] ^ 8,
        c1[5] ^ m1[5] ^ 8,
        c1[6] ^ m1[6] ^ 8,
        c1[7] ^ m1[7] ^ 8
      ] +
      c2
    ).pack('C*')
  )
}

puts m1.pack('C*')
m2 = Array.new(8)

m2[7] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 7] +
      [c2[7] ^ g ^ 1] +
      c3
    ).pack('C*')
  )
}

m2[6] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 6] +
      [
        c2[6] ^ g ^ 2,
        c2[7] ^ m2[7] ^ 2
      ] +
      c3
    ).pack('C*')
  )
}

m2[5] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 5] +
      [
        c2[5] ^ g ^ 3,
        c2[6] ^ m2[6] ^ 3,
        c2[7] ^ m2[7] ^ 3
      ] +
      c3
    ).pack('C*')
  )
}

m2[4] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 4] +
      [
        c2[4] ^ g ^ 4,
        c2[5] ^ m2[5] ^ 4,
        c2[6] ^ m2[6] ^ 4,
        c2[7] ^ m2[7] ^ 4
      ] +
      c3
    ).pack('C*')
  )
}

m2[3] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 3] +
      [
        c2[3] ^ g ^ 5,
        c2[4] ^ m2[4] ^ 5,
        c2[5] ^ m2[5] ^ 5,
        c2[6] ^ m2[6] ^ 5,
        c2[7] ^ m2[7] ^ 5
      ] +
      c3
    ).pack('C*')
  )
}

m2[2] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 2] +
      [
        c2[2] ^ g ^ 6,
        c2[3] ^ m2[3] ^ 6,
        c2[4] ^ m2[4] ^ 6,
        c2[5] ^ m2[5] ^ 6,
        c2[6] ^ m2[6] ^ 6,
        c2[7] ^ m2[7] ^ 6
      ] +
      c3
    ).pack('C*')
  )
}

m2[1] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      c2[0, 1] +
      [
        c2[1] ^ g ^ 7,
        c2[2] ^ m2[2] ^ 7,
        c2[3] ^ m2[3] ^ 7,
        c2[4] ^ m2[4] ^ 7,
        c2[5] ^ m2[5] ^ 7,
        c2[6] ^ m2[6] ^ 7,
        c2[7] ^ m2[7] ^ 7
      ] +
      c3
    ).pack('C*')
  )
}

m2[0] = (0..255).find { |g|
  oracle(
    (
      c0 +
      c1 +
      [
        c2[0] ^ g ^ 8,
        c2[1] ^ m2[1] ^ 8,
        c2[2] ^ m2[2] ^ 8,
        c2[3] ^ m2[3] ^ 8,
        c2[4] ^ m2[4] ^ 8,
        c2[5] ^ m2[5] ^ 8,
        c2[6] ^ m2[6] ^ 8,
        c2[7] ^ m2[7] ^ 8
      ] +
      c3
    ).pack('C*')
  )
}

puts (m1 + m2).pack('C*')
